"""Regression for WHM main/sidebar/plugin-card URL construction."""
import unittest
from pathlib import Path

class MenuConfigTests(unittest.TestCase):
    def test_menu_entry_has_one_cgi_directory(self):
        cfg=dict(line.split('=',1) for line in (Path(__file__).resolve().parents[1]/'take-mfa.conf').read_text().splitlines() if '=' in line)
        self.assertEqual(cfg['entryurl'],'take-mfa.cgi')
        self.assertEqual('/cgi/'+cfg['entryurl'],cfg['url'])
        self.assertNotIn('/cgi/cgi/','/cgi/'+cfg['entryurl'])

if __name__=='__main__':unittest.main()
