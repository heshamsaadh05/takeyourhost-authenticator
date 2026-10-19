"""Local QR renderer. Sensitive input arrives on stdin, never in argv or URLs."""
import json,re,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent/'vendor'))
from qrcodegen import QrCode
from urllib.parse import quote,urlencode

def uri(user,secret):
    if not re.fullmatch(r'[a-z][a-z0-9_]{0,31}',user) or not re.fullmatch(r'[A-Z2-7]{32}',secret):
        raise ValueError('Invalid enrollment')
    issuer='TakeYourHost WHM'
    return 'otpauth://totp/'+quote(issuer+':'+user,safe='')+'?'+urlencode({'secret':secret,'issuer':issuer,'algorithm':'SHA1','digits':'6','period':'30'})

def svg(payload):
    qr=QrCode.encode_text(payload,QrCode.Ecc.MEDIUM)
    n=qr.get_size();size=n+8
    path=' '.join(f'M{x+4},{y+4}h1v1h-1z' for y in range(n) for x in range(n) if qr.get_module(x,y))
    return f'<svg xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Authenticator QR Code" viewBox="0 0 {size} {size}" shape-rendering="crispEdges"><rect width="{size}" height="{size}" fill="#fff"/><path d="{path}" fill="#101a31"/></svg>'

if __name__=='__main__':
    try:
        data=json.loads(sys.stdin.read(1024))
        print(svg(uri(data['user'],data['secret'])))
    except Exception:
        sys.exit(1)
