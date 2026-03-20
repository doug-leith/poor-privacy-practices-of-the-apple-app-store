from mitmproxy import http
import re

def stringify_cookies(cookies: List[Dict]) -> str:
    """
    Creates a cookie string from a list of cookie dicts.
    """
    return ";".join([f"{c['name']}={c['value']}" for c in cookies])


def parse_cookies(cookie_string: str) -> List[Dict[str, str]]:
    """
    Parses a cookie string into a list of cookie dicts.
    """
    cookies = []
    for c in cookie_string.split(";"):
        c = c.strip()
        if c:            
            k, v = c.split("=", 1)
            cookies.append({"name": k, "value": v})
    return cookies

class BlockCookies:

    def request(self, flow:http.HTTPFlow) -> None:
        blocked = ["xp.apple.com","ca.iadsdk.apple.com" ]
        url = flow.request.pretty_url.split('?')[0]
        if re.search("xp.apple.com",url):
            flow.response = http.Response.make(200,"{}",{"content-type":"application/json;charset=utf-8"},)
            print("*******************************Blocked POST",flow.request.pretty_url)
            return
        elif re.search("ca.iadsdk.apple.com",url):
            flow.response = http.Response.make(200)
            print("*******************************Blocked POST",flow.request.pretty_url)
            return

        _req_cookies = flow.request.headers.get_all("cookie")
        url = flow.request.pretty_url.split('?')[0]
        snippets=["p52-buy.itunes.apple.com"] # "se-edge.itunes.apple.com/WebObjects/MZStoreElements.woa/wa/buyButtonMetaData"
        if _req_cookies:
            for s in snippets:
                if re.search(s,url):
                    # leave cookies alone
                    #return
                    _req_cookies_str = flow.request.headers["cookie"]
                    #print( _req_cookies_str)
                    req_cookies = parse_cookies(_req_cookies_str)
                    #print(req_cookies)
                    #ALLOWED=["X-Dsid","pldfltcid", "tv-pldfltcid", "xt-b-ts-19129383683", "amp", "hsaccnt", "xt-src", "itspod", "mt-asn-19129383683", "vrep", "mt-tkn-19129383683", "wosid-lite","mz_at0-19129383683","mz_at_ssl-19129383683","fsas"]
                    ALLOWED=["mt-tkn-19129383683"] #"fsas", "wosid-lite" 
                    cookies = [c for c in req_cookies if c["name"] in ALLOWED]
                    print(cookies)
                    flow.request.headers["cookie"] = stringify_cookies(cookies)
                    return

            print("----",url)
            flow.request.headers["cookie"] = ""

addons = [BlockCookies()]


