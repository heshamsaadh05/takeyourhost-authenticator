"""Decode a rendered SVG independently using a disposable, known test key."""
import importlib.util,re,unittest
from pathlib import Path
from urllib.parse import urlparse,parse_qs,unquote
from PIL import Image,ImageDraw
import zxingcpp

class QRTests(unittest.TestCase):
    def test_svg_can_be_scanned_by_independent_decoder(self):
        p=Path(__file__).resolve().parents[1]/'qr-svg.py'
        spec=importlib.util.spec_from_file_location('mfa_qr_renderer',p)
        m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
        key='A'*32;payload=m.uri('reseller_demo',key);svg=m.svg(payload)
        n=int(re.search(r'viewBox="0 0 (\d+) ',svg)[1]);scale=8
        im=Image.new('RGB',(n*scale,n*scale),'white');draw=ImageDraw.Draw(im)
        for x,y in re.findall(r'M(\d+),(\d+)h1v1h-1z',svg):
            x=int(x)*scale;y=int(y)*scale;draw.rectangle((x,y,x+scale-1,y+scale-1),fill='#101a31')
        decoded=zxingcpp.read_barcode(im)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.text,payload)
        u=urlparse(decoded.text);args=parse_qs(u.query)
        self.assertEqual((u.scheme,u.netloc),('otpauth','totp'))
        self.assertEqual(unquote(u.path),'/TakeYourHost WHM:reseller_demo')
        self.assertEqual(args,{'secret':[key],'issuer':['TakeYourHost WHM'],'algorithm':['SHA1'],'digits':['6'],'period':['30']})

if __name__=='__main__':unittest.main()
