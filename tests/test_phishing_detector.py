import os
import unittest
from unittest.mock import ANY, Mock, patch
import requests
import phishing_detector as api


class PhishingTests(unittest.TestCase):
    def setUp(self):
        self.client = api.app.test_client()

    def test_input_classification(self):
        for text, kind in [('example.com/path?q=1', 'url'), ('https://example.com', 'url'), ('name@example.com', 'email'), ('please verify your account', 'text')]:
            with self.subTest(text=text):
                self.assertEqual(api.parse_input_for_url_or_email(text)['type'], kind)

    def test_payload_validation(self):
        for payload in [[], {}, {'text': None}, {'text': 1}, {'text': ' '}, {'text': 'a' * 8001}]:
            with self.subTest(payload=str(payload)[:40]):
                self.assertEqual(self.client.post('/detect_phishing', json=payload).status_code, 400)
        self.assertEqual(self.client.post('/detect_phishing', data='{', content_type='application/json').status_code, 400)
        self.assertEqual(self.client.post('/detect_phishing', data='x' * 17000, content_type='application/json').status_code, 413)

    @patch.dict(os.environ, {'GOOGLE_API_KEY': 'test-key'})
    @patch.object(api.requests, 'post')
    def test_provider_errors_never_mean_safe(self, post):
        post.side_effect = requests.Timeout('secret-in-provider-url')
        result = api.check_google_safe_browsing('https://example.com')
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertNotIn('secret', result['info'])
        post.side_effect = None
        response = post.return_value = Mock()
        response.raise_for_status.side_effect = requests.HTTPError()
        self.assertEqual(api.check_google_safe_browsing('https://example.com')['status'], 'UNKNOWN')
        response.raise_for_status.side_effect = None
        for body in [{'error': 'quota'}, [], {'matches': 'invalid'}]:
            response.json.return_value = body
            self.assertEqual(api.check_google_safe_browsing('https://example.com')['status'], 'UNKNOWN')

    @patch.dict(os.environ, {'GOOGLE_API_KEY': 'test-key'})
    @patch.object(api.requests, 'post')
    def test_no_match_is_distinct_from_safety(self, post):
        response = post.return_value = Mock()
        for body, expected in [({}, 'NO_KNOWN_THREATS'), ({'matches': [{}]}, 'DANGER')]:
            response.json.return_value = body
            result = self.client.post('/detect_phishing', json={'text': 'example.com'})
            self.assertEqual(result.json['status'], expected)
        post.assert_called_with(ANY, params={'key': 'test-key'}, json=ANY, timeout=8)

    def test_known_email_domain_is_not_authenticated(self):
        result = self.client.post('/detect_phishing', json={'text': 'support@apple.com'})
        self.assertEqual(result.json['status'], 'UNKNOWN')
        self.assertNotIn('100', result.json['analysis'])

    @patch.dict(os.environ, {}, clear=True)
    def test_missing_keys_do_not_break_startup(self):
        self.assertEqual(self.client.get('/health').status_code, 200)
        self.assertEqual(self.client.post('/detect_phishing', json={'text': 'example.com'}).json['status'], 'UNKNOWN')
        self.assertEqual(self.client.post('/detect_phishing', json={'text': 'verify your account'}).status_code, 503)

    @patch.object(api, 'analyze_text')
    def test_text_provider_failure_is_generic(self, analyze):
        analyze.side_effect = api.OpenAIError('sensitive-provider-details')
        result = self.client.post('/detect_phishing', json={'text': 'verify your account'})
        self.assertEqual(result.status_code, 502)
        self.assertNotIn('sensitive', result.json['error'])


if __name__ == '__main__':
    unittest.main()
