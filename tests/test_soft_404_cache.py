import unittest
from unittest.mock import MagicMock, patch

from fuzzstorm import FuzzStorm, SOFT_404_DETECTOR_AVAILABLE


@unittest.skipUnless(SOFT_404_DETECTOR_AVAILABLE, "Soft 404 detector unavailable")
class Soft404CachingTests(unittest.TestCase):
    def setUp(self):
        self.target_url = "http://example.com/"

    def test_detector_reused_and_results_cached(self):
        url = "http://example.com/path"
        with patch("fuzzstorm.Soft404Detector") as detector_cls:
            detector = MagicMock()
            detector.detect_soft_404.return_value = True
            detector_cls.return_value = detector

            fuzzer = FuzzStorm(
                target_url=self.target_url,
                wordlist="dummy.txt",
                extensions=[],
                threads=1,
                detect_soft_404=True,
            )

            first = fuzzer._is_soft_404(url)
            second = fuzzer._is_soft_404(url)

            self.assertTrue(first)
            self.assertTrue(second)
            detector.detect_soft_404.assert_called_once_with(url)
            self.assertIn(url, fuzzer.soft_404s)

    def test_false_results_cached_and_marked_real(self):
        url = "http://example.com/real"
        with patch("fuzzstorm.Soft404Detector") as detector_cls:
            detector = MagicMock()
            detector.detect_soft_404.return_value = False
            detector_cls.return_value = detector

            fuzzer = FuzzStorm(
                target_url=self.target_url,
                wordlist="dummy.txt",
                extensions=[],
                threads=1,
                detect_soft_404=True,
            )

            self.assertFalse(fuzzer._is_soft_404(url))
            self.assertFalse(fuzzer._is_soft_404(url))
            detector.detect_soft_404.assert_called_once_with(url)
            self.assertIn(url, fuzzer.real_200s)
            self.assertIn(url, fuzzer._soft_404_cache)

    def test_detection_disabled_skips_detector(self):
        url = "http://example.com/skip"
        with patch("fuzzstorm.Soft404Detector") as detector_cls:
            fuzzer = FuzzStorm(
                target_url=self.target_url,
                wordlist="dummy.txt",
                extensions=[],
                threads=1,
                detect_soft_404=False,
            )

            self.assertFalse(fuzzer._is_soft_404(url))
            detector_cls.assert_not_called()


if __name__ == "__main__":
    unittest.main()
