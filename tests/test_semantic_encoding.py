"""UTF-8 round trips through the collector's byte-preserving JSON envelope."""
import json
import unittest

from user.analyzer import SemanticExtractor


class SemanticEncodingTest(unittest.TestCase):
    def packet(self, text, direction="prompt", padding=b""):
        body = json.dumps({direction: text}, ensure_ascii=False).encode("utf-8") + padding
        first_line = b"POST /v1/chat HTTP/1.1" if direction == "prompt" else b"HTTP/1.1 200 OK"
        return first_line + b"\r\nContent-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body

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

    def test_chinese_prompt_and_response_round_trip(self):
        prompt = "反复检查同一个计划文件并回报状态 😀"
        extractor = SemanticExtractor()
        request = extractor.feed(self.captured(self.packet(prompt)))
        response = extractor.feed(self.captured(self.packet("ACK:" + prompt, "response"), "response"))
        self.assertEqual([item["text"] for item in request], [prompt])
        self.assertEqual([item["text"] for item in response], ["ACK:" + prompt])

    def test_http_waits_for_the_full_byte_content_length(self):
        text = "中文请求"
        packet = self.packet(text, padding=b"  ")
        extractor = SemanticExtractor()
        self.assertEqual(extractor.feed(self.captured(packet[:-2])), [])
        self.assertEqual([item["text"] for item in extractor.feed(self.captured(packet[-2:]))],
                         [text])

    def check_every_split(self, packet, expected):
        for cut in range(1, len(packet)):
            with self.subTest(cut=cut):
                extractor = SemanticExtractor()
                self.assertEqual(extractor.feed(self.captured(packet[:cut])), [])
                result = extractor.feed(self.captured(packet[cut:]))
                self.assertEqual([item["text"] for item in result], [expected])

    def test_json_handles_every_split_of_multibyte_characters(self):
        text = "中文🙂 café"
        self.check_every_split(json.dumps({"prompt": text}, ensure_ascii=False).encode(), text)

    def test_http_handles_every_split_of_header_and_utf8_body(self):
        text = "中文🙂 café"
        self.check_every_split(self.packet(text), text)

    def test_legacy_collector_envelope_without_marker(self):
        text = "旧采集器中文请求"
        result = SemanticExtractor().feed(self.captured(self.packet(text), marked=False))
        self.assertEqual([item["text"] for item in result], [text])

    def test_unicode_text_inputs_are_not_reinterpreted_as_latin1(self):
        for text in ("中文和 emoji 🙂", "café déjà vu"):
            with self.subTest(text=text):
                raw = self.packet(text)
                # Replayers can also supply an already decoded Unicode payload.
                event = self.captured(raw, marked=False)
                event["payload"] = raw.decode("utf-8")
                result = SemanticExtractor().feed(event)
                self.assertEqual([item["text"] for item in result], [text])

    def test_incomplete_utf8_suffix_is_retained_after_a_complete_document(self):
        first = json.dumps({"prompt": "第一条"}, ensure_ascii=False).encode()
        second = json.dumps({"prompt": "第二条🙂"}, ensure_ascii=False).encode()
        cut = second.index("🙂".encode()) + 2
        extractor = SemanticExtractor()
        initial = extractor.feed(self.captured(first + second[:cut]))
        self.assertEqual([item["text"] for item in initial], ["第一条"])
        remaining = extractor.feed(self.captured(second[cut:]))
        self.assertEqual([item["text"] for item in remaining], ["第二条🙂"])

    def test_credential_redaction_keeps_chinese_text(self):
        text = "检查计划 Authorization: Bearer abc.def 然后继续"
        result = SemanticExtractor().feed(self.captured(self.packet(text)))
        self.assertIn("检查计划", result[0]["text"])
        self.assertIn("然后继续", result[0]["text"])
        self.assertIn("[REDACTED]", result[0]["text"])
        self.assertNotIn("abc.def", result[0]["text"])


if __name__ == "__main__":
    unittest.main()
