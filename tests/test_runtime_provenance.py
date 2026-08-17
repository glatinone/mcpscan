"""Tests for mcpscan.runtime.provenance.ProvenanceWrapper."""

import unittest

from mcpscan.runtime.provenance import ProvenanceWrapper


class TestWrapping(unittest.TestCase):
    def test_wrap_adds_boundary_tag_with_server_and_tool(self):
        wrapper = ProvenanceWrapper()
        result = wrapper.wrap("sunny, 22C", server="weather-mcp", tool="get_weather")

        self.assertEqual(
            result.content,
            '<untrusted_mcp_content server="weather-mcp" tool="get_weather">'
            "sunny, 22C"
            "</untrusted_mcp_content>",
        )
        self.assertFalse(result.truncated)
        self.assertEqual(result.original_length, len("sunny, 22C"))

    def test_custom_tag_name_is_used_consistently(self):
        wrapper = ProvenanceWrapper(tag_name="third_party_output")
        result = wrapper.wrap("data", server="s", tool="t")

        self.assertTrue(
            result.content.startswith('<third_party_output server="s" tool="t">')
        )
        self.assertTrue(result.content.endswith("</third_party_output>"))
        self.assertEqual(wrapper.tag_name, "third_party_output")

    def test_empty_content_is_wrapped_without_error(self):
        wrapper = ProvenanceWrapper()
        result = wrapper.wrap("", server="s", tool="t")

        self.assertEqual(
            result.content,
            '<untrusted_mcp_content server="s" tool="t"></untrusted_mcp_content>',
        )
        self.assertFalse(result.truncated)


class TestSizeCapping(unittest.TestCase):
    def test_content_over_cap_is_truncated(self):
        wrapper = ProvenanceWrapper(max_length=10)
        result = wrapper.wrap("A" * 1000, server="web-mcp", tool="fetch_page")

        self.assertTrue(result.truncated)
        self.assertEqual(result.original_length, 1000)
        self.assertIn("... [truncated]", result.content)
        self.assertTrue(
            result.content.startswith(
                '<untrusted_mcp_content server="web-mcp" tool="fetch_page">'
            )
        )
        self.assertTrue(result.content.endswith("</untrusted_mcp_content>"))

    def test_content_at_exactly_the_cap_is_not_truncated(self):
        wrapper = ProvenanceWrapper(max_length=10)
        result = wrapper.wrap("A" * 10, server="s", tool="t")

        self.assertFalse(result.truncated)
        self.assertNotIn("... [truncated]", result.content)


class TestSystemPromptAddendum(unittest.TestCase):
    def test_addendum_references_the_configured_tag(self):
        wrapper = ProvenanceWrapper(tag_name="custom_tag")
        addendum = wrapper.system_prompt_addendum()

        self.assertIn("<custom_tag>", addendum)
        self.assertIn("third-party MCP server", addendum)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
