"""Static, consent and privacy boundaries for IMPERIAL EYE's local UI."""
from pathlib import Path
import unittest


ROOT = Path("security/imperial_eye/web")


class EyeWebTests(unittest.TestCase):
    def setUp(self):
        self.html = (ROOT/"index.html").read_text(encoding="utf-8")
        self.js = (ROOT/"assets/eye.js").read_text(encoding="utf-8")
        self.css = (ROOT/"assets/eye.css").read_text(encoding="utf-8")

    def test_client_assets_present(self):
        self.assertIn('href="assets/eye.css"', self.html)
        self.assertIn('src="assets/eye.js"', self.html)
        self.assertTrue(self.css)

    def test_strict_csp_prohibits_external_frames(self):
        self.assertIn("default-src 'none'", self.html)
        self.assertIn("frame-src 'none'", self.html)
        self.assertIn("connect-src 'self'", self.html)
        self.assertNotIn("'unsafe-inline'", self.html)

    def test_no_raw_face_scanning_or_templates(self):
        self.assertNotIn("getUserMedia(", self.js)
        self.assertNotIn("faceRecognition", self.js)
        self.assertNotIn("faceDescriptors", self.js)
        self.assertNotIn("uploadFace", self.js)
        self.assertIn("Raw face scans never go to IMPERIAL Core", self.html)

    def test_owner_auth_never_unlocks_from_client(self):
        self.assertIn('userVerification:"required"', self.js)
        self.assertIn("/api/imperial-eye/owner/challenge", self.js)
        self.assertIn("/api/imperial-eye/owner/assertion", self.js)
        self.assertIn("Owner Authority Guard and Approval Gateway", self.js)
        self.assertIn("Access denied", self.js)

    def test_no_external_feed_proxies(self):
        self.assertNotIn("rtsp://", self.html+self.js)
        self.assertNotIn("imageCapture", self.html+self.js)
        self.assertNotIn("video.src", self.js)
        self.assertIn("Publisher portal", self.html)

    def test_links_have_opener_protection(self):
        self.assertIn('a.rel = "noopener noreferrer"', self.js)
        self.assertIn('a.target = "_blank"', self.js)

    def test_allowlisted_official_hosts_only(self):
        self.assertIn('"511ny.org"', self.js)
        self.assertIn('"fintraffic.fi"', self.js)
        self.assertIn('url.protocol !== "https:"', self.js)

    def test_map_does_not_claim_camera_coordinates(self):
        self.assertIn("NOT CAMERA LOCATIONS", self.html)
        self.assertIn("regional center, not camera coordinates", self.js)


if __name__=="__main__":
    unittest.main()
