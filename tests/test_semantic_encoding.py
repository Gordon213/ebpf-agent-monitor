"""UTF-8 round trips through the collector's byte-preserving JSON envelope."""
import json
import unittest

from user.analyzer import SemanticExtractor


class SemanticEncodingTest(unittest.TestCase):
# 构造一个被分析的 TLS 事件包。
    def packet(self, text, direction="prompt", padding=b""):
        body = json.dumps({direction: text}, ensure_ascii=False).encode("utf-8") + padding
        first_line = b"POST /v1/chat HTTP/1.1" if direction == "prompt" else b"HTTP/1.1 200 OK"
        return first_line + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

# 构造 collector JSON 形状的采集事件。
    def captured(self, data, direction="prompt", marked=True):
        event = {
            "type": "tls_write" if direction == "prompt" else "tls_read",
            "agent_id": 1, "tgid": 100, "timestamp_ns": 1_000_000_000,
            "payload": data.decode("latin-1"), "data_len": len(data), "data_size": len(data),
        }
        if marked:
            event["payload_encoding"] = "latin-1"
        # Exactly like json_bytes(): one JSON code point for every captured byte.
        return json.loads(json.dumps(event, ensure_ascii=True))

# 中文 Prompt/Response 经过采集与分析后要能原样还原。
    def test_chinese_prompt_and_response_round_trip(self):
        prompt = "反复检查同一个计划文件并回报状态 😀"
        extractor = SemanticExtractor()
        request = extractor.feed(self.captured(self.packet(prompt)))
        response = extractor.feed(self.captured(self.packet("ACK:" + prompt, "response"), "response"))
        self.assertEqual([item["text"] for item in request], [prompt])
        self.assertEqual([item["text"] for item in response], ["ACK:" + prompt])

# HTTP 解析要等到 Content-Length 声明的全部字节，不能提前截断。
    def test_http_waits_for_the_full_byte_content_length(self):
        text = "中文请求"
        packet = self.packet(text, padding=b"  ")
        extractor = SemanticExtractor()
        self.assertEqual(extractor.feed(self.captured(packet[:-2])), [])
        self.assertEqual([item["text"] for item in extractor.feed(self.captured(packet[-2:]))],
                         [text])

# 辅助函数：把包切成两片，验证每一种切分都不丢内容。
    def check_every_split(self, packet, expected):
        for cut in range(1, len(packet)):
            with self.subTest(cut=cut):
                extractor = SemanticExtractor()
                self.assertEqual(extractor.feed(self.captured(packet[:cut])), [])
                result = extractor.feed(self.captured(packet[cut:]))
                self.assertEqual([item["text"] for item in result], [expected])

# 多字节字符在任意位置被切断都要能正确重组。
    def test_json_handles_every_split_of_multibyte_characters(self):
        text = "中文🙂 café"
        self.check_every_split(json.dumps({"prompt": text}, ensure_ascii=False).encode(), text)

# HTTP 头与 UTF-8 正文的每一种切分都要能解析。
    def test_http_handles_every_split_of_header_and_utf8_body(self):
        text = "中文🙂 café"
        self.check_every_split(self.packet(text), text)

# 兼容不带标记的旧版采集器事件格式。
    def test_legacy_collector_envelope_without_marker(self):
        text = "旧采集器中文请求"
        result = SemanticExtractor().feed(self.captured(self.packet(text), marked=False))
        self.assertEqual([item["text"] for item in result], [text])

# 已经是 Unicode 的文本输入不能被当作 latin-1 重新解码。
    def test_unicode_text_inputs_are_not_reinterpreted_as_latin1(self):
        for text in ("中文和 emoji 🙂", "café déjà vu"):
            with self.subTest(text=text):
                raw = self.packet(text)
                # Replayers can also supply an already decoded Unicode payload.
                event = self.captured(raw, marked=False)
                event["payload"] = raw.decode("utf-8")
                result = SemanticExtractor().feed(event)
                self.assertEqual([item["text"] for item in result], [text])

# 完整文档之后残留的不完整 UTF-8 后缀要保留给下一片。
    def test_incomplete_utf8_suffix_is_retained_after_a_complete_document(self):
        first = json.dumps({"prompt": "第一条"}, ensure_ascii=False).encode()
        second = json.dumps({"prompt": "第二条🙂"}, ensure_ascii=False).encode()
        cut = second.index("🙂".encode()) + 2
        extractor = SemanticExtractor()
        initial = extractor.feed(self.captured(first + second[:cut]))
        self.assertEqual([item["text"] for item in initial], ["第一条"])
        remaining = extractor.feed(self.captured(second[cut:]))
        self.assertEqual([item["text"] for item in remaining], ["第二条🙂"])

# 凭据脱敏后中文文本要保持可读，不能被破坏。
    def test_credential_redaction_keeps_chinese_text(self):
        text = "检查计划 Authorization: Bearer abc.def 然后继续"
        result = SemanticExtractor().feed(self.captured(self.packet(text)))
        self.assertIn("检查计划", result[0]["text"])
        self.assertIn("然后继续", result[0]["text"])
        self.assertIn("[REDACTED]", result[0]["text"])
        self.assertNotIn("abc.def", result[0]["text"])


if __name__ == "__main__":
    unittest.main()
