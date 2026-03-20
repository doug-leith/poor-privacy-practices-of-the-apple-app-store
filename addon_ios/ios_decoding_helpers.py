import subprocess
import textwrap
import sys
import os
import urllib.parse
import zlib
import base64
import tempfile
from mitmproxy import http, tcp
import struct
import re
import warnings
import datetime
from mitmproxy.utils import strutils
from mitmproxy import ctx
import plistlib
import pprint
import traceback
import types
import hashlib
import json

# suppress protobuf deprecation warnings, at least for now
warnings.filterwarnings("ignore")

# add folder where this script is to python search path (so can find helpers)
mypath = os.path.dirname(os.path.realpath(__file__))
sys.path.append(mypath)

#print(sys.version)
#print(text_format.__file__)

def printBinaryString(string):
    for c in string:
        if c >= 32 and c <= 127:
            print('%c' % c, end='')
        else:
            print('%X' % c, end='')
    print()

def stringContains(string, snippets):
    for s in snippets:
        if s in string:
            return True
    return False

def printUsingMimeType(payload,mimeType,tag="POST Body"):
    #print("mimetype:",mimeType)
    if len(payload)==0 or payload==None:
        return
    if mimeType is None:
        print(payload)
        return
    if stringContains(mimeType,['application/x-protobuf', 'application/x-protobuffer','application/protobuf'
                    ]):
        res = try_decode_pb_array(tag+" ("+mimeType+" decoded)", payload, decode_pb)
        if "Dumping binary data" in res:
            # didn't decode as a protobuf, try gRPC
            res2 = decode_gRPC(payload, decode_pb, tag+" ("+mimeType+" decoded as gRPC)")
            if "Invalid gRPC message" in res2:
                print(payload)
            else:
                print(res2)
        else:
            print(res)
    elif mimeType == "application/ocsp-response":
        print(tag+" ("+mimeType+" decoded):")
        print(decode_ocsp_response(payload))  
    elif mimeType == 'application/zip' or (mimeType == 'binary/octet-stream' and payload[:2]== b'PK'):
        print(tag+" ("+mimeType+" decoded):")
        print(decode_zip(payload))    
    elif mimeType == 'application/x-gzip' or mimeType == 'application/gzip':
        print(tag+" ("+mimeType+" decoded):")
        try:
            print(zlib.decompress(payload, 32+zlib.MAX_WBITS))  
        except:
            print(payload)               
    elif mimeType == 'application/grpc':
        print(decode_gRPC(payload, decode_pb, tag+" ("+mimeType+" decoded)"))
    elif 'application/json' in mimeType: 
        print(tag+" ("+mimeType+"):")
        import json
        try:
            # try to decode and print json nicely
            print(json.loads(payload.decode('utf8')))
        except:
            # print raw text
            print(payload.decode('utf8'))
    elif mimeType == 'application/cbor':
        print(tag+" ("+mimeType+" decoded):")
        print(cbor2.loads(payload))
    elif 'text' in mimeType or 'xml' in mimeType or 'application/x-apple-plist' in mimeType:
        print(tag+" ("+mimeType+"):")
        try:
            print(payload.decode('utf8'))
        except:
            print(payload)
    elif mimeType == 'application/x-www-form-urlencoded':
        try:
            print(tag+" ("+mimeType+" decoded):")
            print(urllib.parse.unquote(payload.decode('utf8')))
        except:
            print(tag+":")
            print(payload)
    elif mimeType ==  "image/heic" or mimeType == 'image/png':
        print(tag+" ("+mimeType+"):")
        print("<image>")
    elif mimeType == "video/mp4":
        print(tag+" ("+mimeType+"):")
        print("<video>")
    else:
        print(tag+" ("+mimeType+"):")
        print(payload)

def printHeaders(flowheaders, type=""):
    cookies = ""
    for hh in flowheaders:
        h={'name':hh, 'value':flowheaders[hh]}
        if 'cookie' in h['name'] or 'Cookie' in h['name'] or 'set-cookie' in h['name'] or 'Set-Cookie' in h['name']:
            cookies = cookies+h['name']+": " + h['value']+"\n"
    if len(cookies)>0:
        print(type+" cookies:")
        print(cookies)

    request_content_sum =0 
    print(type+" headers:")
    for hh in flowheaders:
        h={'name':hh, 'value':flowheaders[hh]}
        print(h['name'], ':', h['value'])
        request_content_sum += len(h['value'])
    return request_content_sum

def printRequest(url, request):

    request_content_sum=0
    if len(request.headers) > 0:
        # print headers
        request_content_sum += printHeaders(request.headers, "Request")   

    req = request.path.split("?")
    req = req[0]
    for q in request.query:
        request_content_sum += len(request.query[q])
        # decode query parameters
        if q == "bpb" and "/maps/vt/proto" in url:
            #google maps
            try:
                val=request.query[q]
                # need to use urlsafe of base64 variant here
                buf = base64.urlsafe_b64decode(val)
                print("Decoded "+q+" query parameter:\n", decode_pb(buf,verbose=True,debug=False))
            except Exception as e:
                print("***ERROR: ",e)

    # handlers for known google post data formats
    request_decoders={
    'gs-loc.apple.com/clls/wloc':decode_apple_wlocrequest,
    'gsp[0-9]+-ssl.ls.apple.com/wifi_request':decode_apple_arpc,
    'gsp-ssl.ls.apple.com/dispatcher.arpc':decode_apple_arpc,
    'gsp[0-9]+-ssl.apple.com/hvr/trc':decode_apple_arpc,
    'gsp[0-9]+-ssl.ls.apple.com/hvr/v3/use':decode_apple_arpc,
    'gsp-ssl.ls.apple.com/ab.arpc':decode_apple_arpc,
#   'gsp10-ssl.ls.apple.com/hvr/wcq':decode_apple_arpc
    'mask-api.icloud.com/v1/fetchAuthTokens':decode_pb,
    'iadsdk.apple.com/adserver/2.6/optout/optout_optin':decode_iad,
    'iadsdk.apple.com/adserver/2.6/segment/update':decode_iad,
    'humb.apple.com/humbug/baa':decode_applexml,
    'init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag':decode_applexml,
    'init-kt.apple.com/init/getBag':decode_applexml,
    'xp.apple.com/report': decode_applexp_report,
    'xp.apple.com/register': decode_applexp_register,
    'amp-api-edge.apps.apple.com/v1/engagement': decode_ampapiedge_req,
    }

    postData = ""
    requestMimeType = ""
    if request.method == "POST":
        postData = request.content
        request_content_sum += len(postData)
        if 'Content-Type' in request.headers:
            requestMimeType = request.headers['Content-Type'] 
        elif 'content-type' in request.headers:
            requestMimeType = request.headers['content-type']

    if (postData is not None) and (len(postData) > 0):
        # decode known google formats
        decoded=False
        for snippet in request_decoders:
            #if snippet in url:
            if re.search(snippet,url):
                print("POST Body (decoded):")
                print(request_decoders[snippet](postData))
                decoded=True
                break
        if not decoded:
            printUsingMimeType(postData,requestMimeType)

    return request_content_sum

def printResponse(url, response, verboseResponse=True):

    # take a look at the content of the response ...

    if len(response. headers) > 0:
        # print headers
        printHeaders(response.headers, "Response")   

    # handlers for known google formats
    response_decoders={
    'swallow.apple.com/siri.sidecars.auth.AuthSession/GetCertificate': decodeCerts,
    'gs-loc.apple.com/clls/wloc':decode_apple_wlocresponse,
    'gsp[0-9]+-ssl.ls.apple.com/wifi_request':decode_apple_arpc_response,
    'gsp-ssl.ls.apple.com/ab.arpc':decode_apple_arpc_response,
    'gsp[0-9]+-ssl.ls.apple.com/hvr/v3/use':decode_apple_arpc_response,
    'gspe[0-9]+-ssl.ls.apple.com/geo_manifest/dynamic/config':decode_pb,
    'mask-api.icloud.com/v2_3/fetchConfigFile':decode_pb,
    'mask-api.icloud.com/v1/fetchAuthTokens':decode_pb,
    'iadsdk.apple.com/adserver/2.6/optout/optout_optin':decode_iad,
    'iadsdk.apple.com/adserver/2.6/segment/update':decode_iad,
    'apps.mzstatic.com/content/on-device-journeys-exporter/content/ums-locales.json':base64.b64decode,
    'tr.iadsdk.apple.com/adserver/2.6/settings':decode_adserver,
    'cf.iadsdk.apple.com/adserver/2.6/config':decode_adserver,
    'humb.apple.com/humbug/baa':decode_certs,
    'amp-api-edge.apps.apple.com/v1/engagement': decode_ampapiedge_resp,
    'gspe21-ssl.ls.apple.com/other': decode_pb,
    }
    responseMimeType=None
    #if re.search('\\.gz$',url):
    #    # force decode of gzipped files 
    #    responseMimeType='application/gzip'
    if ('Content-Type' in response.headers):
        responseMimeType=response.headers['Content-Type']
    elif ('content-type' in response.headers):
        responseMimeType=response.headers['content-type'] 

    if response.content is not None and len(response.content) > 0:
        responseData = response.content
    else:
        responseData = None

    if (responseData is not None) and (len(responseData) > 0):
        # decode known formats
        decoded=False
        for snippet in response_decoders:
            #if snippet in url:
            if re.search(snippet,url):
                print("Response data (decoded):")
                print(response_decoders[snippet](responseData))
                decoded=True
                break
        if not decoded:
            if verboseResponse or stringContains(url,['grandslam','swallow.apple.com','gateway.icloud.com/ckdatabase/api/client/query/retrieve']):
                    printUsingMimeType(responseData,responseMimeType,"Response data")
            elif len(responseData) <= 1000:
                printUsingMimeType(responseData,responseMimeType,"Response data")
            else:
                print("Response data (truncated):")
                print(responseData[:1000],"<truncated>")

    
#from mitm_protobuf import format_pbuf
#import difflib
def decode_pb(bb, verbose=True, debug=False):
    # try to decode a protobuf without knowing the schema, usually works fine
    # but there can be ambiguity in encoding and so result may not be quite what we'd
    # like e.g. an embedded protobuf might be parsed as a bytes field.
    if debug:
        fname='/tmp/bytes'
        f = open(fname, 'wb')
    else:
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
    f.write(bb)
    f.close()
    try:       
        res = subprocess.check_output("cat "+fname+" | protoc --decode_raw", 
                                       shell=True, stderr=subprocess.STDOUT, text=True)
        
        '''
        # test of alternative raw decoding approach, but it makes different choices/guesses from protoc
        mitm_res = format_pbuf(bb)        
        diff="".join(difflib.ndiff(res.splitlines(keepends=True),mitm_res.splitlines(keepends=True)))
        if len(diff)>0:
            print("+++mitm")
            print(diff)
            print("---mitm")
        '''
        return res
    except subprocess.CalledProcessError as e:  
        res=""        
        if verbose:
            res="***ERROR: "+str(e.output)+"\n"
            res=res+str(e)+"\n"
            return "Failed to parse input\n"+res
        return "Failed"

def print_wrapped(*args, indent=0):
    import io
    import textwrap

    # print to string
    output = io.StringIO()
    print(*args, file=output)
    contents = output.getvalue()
    output.close()

    # now wrap string
    for line in textwrap.wrap(contents):
        print('\t'*indent,line)

def decode_certs(data):
    res=""
    data=data.decode('utf8')
    certs = data.split("-----BEGIN CERTIFICATE-----")
    for c in certs:
        if len(c)==0:
            continue
        f = tempfile.NamedTemporaryFile(mode='w',delete=False)
        fname=f.name
        f.write("-----BEGIN CERTIFICATE-----")
        f.write(c)
        f.close()
        try:
            out = res+subprocess.check_output("openssl x509 -noout -text -certopt ext_dump -in "+fname, 
                                        shell=True, stderr=subprocess.STDOUT, text=True)
            res=res+out
        except Exception as e:
            res=res+"***ERROR "+str(e)+"\n"+c+"\n"
    return res


def decode_img4(data):

    f = tempfile.NamedTemporaryFile(delete=False)
    fname=f.name
    f.write(data)
    f.close()
    try:
        # use "brew install ipsw" to install ipsw
        if data[6:10] == b'IM4M':
            res = subprocess.check_output("ipsw img4 im4m info --no-color "+fname, 
                                shell=True, stderr=subprocess.STDOUT, text=True)
        elif data[6:10] == b'IM4P':
            res = subprocess.check_output("ipsw img4 im4p info --no-color "+fname, 
                                shell=True, stderr=subprocess.STDOUT, text=True)
        elif data[6:10] == b'IMG4':
            res = subprocess.check_output("ipsw img4 info --no-color "+fname, 
                                shell=True, stderr=subprocess.STDOUT, text=True)
        else:
            return "***ERROR "+data[:16]
        # remove nasty escape codes from text
        # https://stackoverflow.com/questions/14693701/how-can-i-remove-the-ansi-escape-sequences-from-a-string-in-python
        # 7-bit C1 ANSI sequences
        ansi_escape = re.compile(r'''
            \x1B  # ESC
            (?:   # 7-bit C1 Fe (except CSI)
                [@-Z\\-_]
            |     # or [ for CSI, followed by a control sequence
                \[
                [0-?]*  # Parameter bytes
                [ -/]*  # Intermediate bytes
                [@-~]   # Final byte
            )
        ''', re.VERBOSE)
        return ansi_escape.sub('', res)
    except Exception as e:
        #print("***ERROR ",e)
        return "***ERROR "+str(e)


def decode_applexml(data, indent=0):
    import xml.etree.ElementTree as ET
    root = ET.ElementTree(ET.fromstring(data)).getroot()
    dict_ = root[0]
    for i in range(len(dict_)):
        #print(dict_[i].tag, dict_[i].text)
        if dict_[i].tag == 'data':
            decoded = decodeBase64(dict_[i].text)
            try:
                # try to decode as text
                res=decoded.decode('utf8')
                try:
                    # try to decode text as xml
                    print('\t'*indent,'<data xml>')
                    decode_applexml(res,indent=indent+1)
                    print('\t'*indent,'</data>')
                except:
                    # print the text
                    print_wrapped('<data text>'+res+'</data>', indent=indent)
            except:
                # else try to decode as img4 
                res=decode_img4(decoded)
                if '***ERROR' in res:
                    # else print as binary
                    #print_wrapped('<data binary>',decoded,'</data>', indent=indent)
                    print('<data binary>',decoded,'</data>')
                else:
                    print('\t'*indent,'<data img4>',res,'</data>')
        else:
            print('\t'*indent,f'<{dict_[i].tag}>{dict_[i].text}</{dict_[i].tag}>')       


def decode_ocsp_response(data):
    from cryptography.x509 import ocsp
    import warnings
    warnings.filterwarnings("ignore")
    res=ocsp.load_der_ocsp_response(data)
    dump_object('response',res)

    warnings.filterwarnings("default")

def decode_iad(buf, verbose=True):
    #8 byte header
    extra=struct.unpack('!I',buf[:4])
    payloadlength=struct.unpack('!I',buf[4:8])
    res=f"apple header: extra={extra[0]}, length={payloadlength[0]}"
    try:
        return res+"\n"+decode_pb(buf[8:8+payloadlength[0]])
    except Exception as e:
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_adserver(buf, verbose=True):
    import struct
    extra=str(buf[:8])
    payloadlength=struct.unpack('!h',buf[6:8])
    res=f"apple header: extra={extra}, length={payloadlength[0]}"
    #print(len(buf[8:]))
    try:
        return res+"\n"+decode_pb(buf[8:8+payloadlength[0]])
    except Exception as e:
        if verbose:
            print("***ERROR: ", e)
        return "Failed"

def decode_apple_arpc_response(buf, verbose=True):
    extra=str(buf[:6])
    payloadlength=struct.unpack('!I',buf[6:10])
    res=f"apple header: extra={extra}, length={payloadlength[0]}"
    try:
        return res+"\n"+decode_pb(buf[10:10+payloadlength[0]])
    except Exception as e:
        if verbose:
            print("***ERROR: ", e)
        return "Failed"

def decode_apple_arpc(buf, verbose=True):
    # read header
    # https://github.com/acheong08/apple-corelocation-experiments/blob/main/lib/arpc.go
    posn=0
    version = struct.unpack('!H',buf[posn:posn+2]); posn=posn+2
    strlength =buf[posn]*256+buf[posn+1]; posn=posn+2
    locale = buf[posn:posn+strlength].decode('utf8'); posn=posn+strlength
    strlength =buf[posn]*256+buf[posn+1]; posn=posn+2
    appIdentifier = buf[posn:posn+strlength].decode('utf8'); posn=posn+strlength
    strlength =buf[posn]*256+buf[posn+1]; posn=posn+2
    osVersion = buf[posn:posn+strlength].decode('utf8'); posn=posn+strlength
    functionid = struct.unpack('!I',buf[posn:posn+4]); posn=posn+4 
    payloadlength=struct.unpack('!I',buf[posn:posn+4]); posn=posn+4
    res = f"apple header: version={version[0]}, locale={locale}, app={appIdentifier}, osVersion={osVersion}, functionId={functionid[0]}, length={payloadlength[0]}"
    try:
        print(buf)
        return res+"\n"+decode_pb(buf[posn:posn+payloadlength[0]])
    except Exception as e:
        if verbose:
            print("***ERROR: ",e)
            print(buf)
        return "Failed"

def decode_apple_aprc_header(buf):
    posn=0
    version = struct.unpack('!H',buf[posn:posn+2]); posn=posn+2
    if version[0] == 1:
        strlength =buf[posn]*256+buf[posn+1]; posn=posn+2
        locale = buf[posn:posn+strlength].decode('utf8'); posn=posn+strlength
        strlength =buf[posn]*256+buf[posn+1]; posn=posn+2
        appIdentifier = buf[posn:posn+strlength].decode('utf8'); posn=posn+strlength
        strlength =buf[posn]*256+buf[posn+1]; posn=posn+2
        osVersion = buf[posn:posn+strlength].decode('utf8'); posn=posn+strlength
        functionId = struct.unpack('!I',buf[posn:posn+4]); posn=posn+4 
        payloadlength=struct.unpack('!I',buf[posn:posn+4]); posn=posn+4
        res=f"apple header: version={version[0]}, locale={locale}, app={appIdentifier}, osVersion={osVersion}, functionid={functionId[0]}"
    elif version[0] == 2:
        strlength =buf[posn]*256+buf[posn+1]; posn=posn+2
        locale = buf[posn:posn+strlength].decode('utf8'); posn=posn+strlength
        strlength =buf[posn]*256+buf[posn+1]; posn=posn+2
        appIdentifier = buf[posn:posn+strlength].decode('utf8'); posn=posn+strlength
        strlength =buf[posn]*256+buf[posn+1]; posn=posn+2
        osVersion = buf[posn:posn+strlength].decode('utf8'); posn=posn+strlength
        res=f"apple header: version={version[0]}, locale={locale}, app={appIdentifier}, osVersion={osVersion}"
    else:
        res=f"***ERROR: unknown apple header version {version[0]}"
        posn=-1
    return (res,posn) 

def decode_apple_wlocrequest(buf, verbose=True):
    # special case of apple_arpc, where we know protobuf format
    # https://github.com/acheong08/apple-corelocation-experiments/blob/main/lib/arpc.go
    (res,posn)=decode_apple_aprc_header(buf)
    if posn>0:
        # and decode the body as a protobuf
        f = tempfile.NamedTemporaryFile(delete=False)
        fname=f.name
        f.write(buf[posn:])
        f.close()
        try:
            return res+"\n"+subprocess.check_output("protoc --decode=\"AppleWLoc\" -I='"+mypath+"' ios_location.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:        
            if verbose:
                print("***ERROR AppleWloc pb decode: ",e)
            try:
                # try to decode as raw protobuf
                return res+"\n"+decode_pb(buf[posn:posn+payloadlength[0]])
            except Exception as e:
                if verbose:
                    print("***ERROR raw pb decode: ",e)           
            return "Failed"
    else:
        if verbose:
            print(res)           
        return "Failed"

def decode_apple_wlocresponse(buf, verbose=True):
    # https://github.com/acheong08/apple-corelocation-experiments/blob/main/lib/wloc.go
    f = tempfile.NamedTemporaryFile(delete=False)
    fname=f.name
    f.write(buf[10:]) # first 10 bytes are header
    f.close()
    res=str(buf[0:10]) # keep header
    try:
        return "apple header: "+res+"\n"+subprocess.check_output("protoc --decode=\"AppleWLoc\" -I='"+mypath+"' ios_location.proto  <"+fname, shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:        
        if verbose:
            print("***ERROR: ",e)
        return "Failed"

def decode_applexp_register(data, verbose=True):
    if data is not None:
        res=str(data) 
    else:
        res=""
    return res+"\n+++XP register"

def decode_applexp_report(data, verbose=True):
    try:
        res=data.decode('utf8')
        res_summary=""
        xp_telemetry = json.loads(data)
        interesting = ['eventTime','eventType','app','dsId','clientId','userId','clientEventId','iAdId', 'iAdMetadata','iAdPlacementId',
                    'iAdImpressionId','iAdMetadata', 'adamId', 'iAdAppStoreClientRequestId', 'pageId', 'pageCustomId','actionUrl', 'experimentId', 
                    'pageExperimentId', 'searchTerm', 'page', 'pageDetails', 'pageUrl', 'data.search.dataSetId', 'term', 
                    'targetType', 'searchTerm','actionType']
        ids = ['eventTime','eventType','dsId','clientId','userId','clientEventId','iAdId', 'iAdMetadata','iAdPlacementId',
                    'iAdImpressionId','iAdMetadata', 'adamId', 'iAdAppStoreClientRequestId', 'pageId', 'pageCustomId', 'experimentId', 
                    'pageExperimentId', 'pageUrl', 'data.search.dataSetId']
        for event in xp_telemetry['events']:
            res=res+'\n+++XP report '
            res_summary="\n+++XP_IDS report "
            for f in interesting:
                if f in  event:
                    res=res+f+"="+str(event[f])+","
                    res_summary=res_summary+f+","
            for f in ids:
                if f in  event:
                    res_summary=res_summary+f+","
            if 'impressions' in event:
                for impression in event['impressions']:
                    for f in interesting :
                        if f in  impression:
                            res=res+f+"="+str(impression[f])+","
                    for f in ids :
                        if f in  impression:
                            res_summary=res_summary+f+","
            if 'iAd' in event:
                impression = event['iAd']
                for f in interesting:
                    if f in  impression:
                        res=res+f+"="+str(impression[f])+","
                for f in ids :
                    if f in  impression:
                        res_summary=res_summary+f+","
            res=res+res_summary
        return res
    except Exception as e:
        if verbose:
            print("***ERROR: ",e)
        return data

def decode_ampapiedge_req(data,verbose=True):
    try:
        res=data.decode('utf8')
        telemetry = json.loads(data)
        res=res+'\n+++AMP_REQ '
        #for adRequest in telemetry['data']:
        #    res=res+"€"
        #    res=res+adRequest['type']['value']+","
        #    res=res+"deviceRequestID:"+adRequest['AdRequest']['deviceRequestID']+","
        #    res=res+"clientId:"+adRequest['properties']['clientId']
        return res
    except Exception as e:
        if verbose:
            print("***ERROR: ",e)
        return data

def decode_ampapiedge_resp(data,verbose=True):
    try:
        res=data.decode('utf8')
        adverts = json.loads(data)
        res=res+"\nDecoded:\n"
        for ad in adverts['results']['ads']:
            if ('meta' in ad):
                meta=ad['meta']
                adResult=json.loads(meta['adResult'])
                decoded = decodeBase64protobuf(adResult['metadata'], decode_pb)
                # removed escaped \"
                decoded.replace('\"','"')
                adResult['metadata']=decoded
                ad['meta']['adResult']=json.dumps(adResult)
            res=res+json.dumps(ad,indent=4)+"\n"
        return res
    except Exception as e:
        if verbose:
            print("***ERROR: ",e)
            import traceback
            print(traceback.format_exc())
        return data

def decode_zip(data):
    import zipfile
    import plistlib
    f = tempfile.NamedTemporaryFile(delete=False)
    f.write(data)
    f.close()
    d = tempfile.TemporaryDirectory()
    with zipfile.ZipFile(f.name, 'r') as zip_ref:
        zip_ref.extractall(d.name)
    from pathlib import Path
    pathlist = Path(d.name).rglob('*')
    for path in pathlist:
        # because path is object not string
        path_in_str = str(path)
        print(path_in_str)
        if path_in_str.endswith('.plist'):
            f=open(path_in_str,'rb')
            #print(plistlib.load(f))
            pprint.pprint(plistlib.load(f))
            f.close()
    d.cleanup()

def decodeCerts(certchain):
    # x509 cert starts with b'0x82' then two bytes giving length, so use this to parse out cert chain
    # see https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    res=""
    temp = certchain
    i=0
    while i < len(temp):
        #print(temp[i:i+1])
        if temp[i:i+2]==b'0\x82':
            i=i-4
            break
        else:
            i=i+1
    temp=temp[i:]
    while len(temp)>4:
        #print(temp[:2])
        length=struct.unpack('!H',temp[2:4])
        #print(length,len(temp))
        #print(temp[0:length[0]+4])
        cert = x509.load_der_x509_certificate(temp[4:length[0]+4])
        res=res+"X509 certificate:\n"
        for property in ['issuer','subject','not_valid_before_utc','not_valid_after_utc','serial_number',
            'signature_algorithm_oid']: #,'extensions']:
            try:
                res=res+"\t"+property+":"+str(getattr(cert,property))+"\n"
            except Exception as e:
                print("***ERROR: ",e)
        try:
            res=res+"\t"+"public key:"+str(cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))+"\n"
        except:
            pass
        #print(res)
        temp=temp[length[0]+4:]
    return res

def decode_gRPC(data,decoder,tag="POST Body (gRPC decoded)"):
    res=""
    orig_data = data
    while data:
        try:
            compressed, length = struct.unpack('!?I', data[:5])
            message = struct.unpack('!%is'%length, data[5:5+length])[0]
            if compressed:
                # assume gzip, actual compression has to be parsed from 'grpc-encoding' header
                # see also: https://www.oreilly.com/library/view/grpc-up-and/9781492058328/ch04.html
                message = zlib.decompress(message, 32+zlib.MAX_WBITS)
        except Exception as e: 
            #print(repr(e))
            #print("compressed ",compressed, "length", length, "data len ",len(orig_data),len(data))
            #print("Invalid gRPC message: ",(orig_data,))
            #print("***ERROR: ",e)
            return "Invalid gRPC message: "+str(orig_data)
        res=res+try_decode_pb_array(tag, message, decoder)+"\n"
        data = data[5+length:]
    return(res)

def base64padding(header):
    if len(header) % 4 == 2:
        extras="=="
    elif len(header) % 4 == 3:
        extras="="
    else:
        extras=""
    return extras

def decodeBase64(header):
    return base64.b64decode(header + base64padding(header))

def urlsafe_decodeBase64(header):
    return base64.urlsafe_b64decode(header + base64padding(header))


def decodeBase64ZippedProto(header):
    try:
        buf = urlsafe_decodeBase64(header)
        unzipped = zlib.decompress(buf, 32 + zlib.MAX_WBITS)
        return decode_pb(unzipped)
    except Exception as e:
        print("***ERROR: ",e)
        return "Failed"

def decodeBase64protobuf(header, decoder):
    decoded = base64.b64decode(header + base64padding(header))
    return decoder(decoded)

def bytes_to_escaped_str(
    data: bytes, keep_spacing: bool = False, escape_single_quotes: bool = False
) -> str:
    """
    Take bytes and return a safe string that can be displayed to the user.
    Single quotes are always escaped, double quotes are never escaped:
        "'" + bytes_to_escaped_str(...) + "'"
    gives a valid Python string.
    Args:
        keep_spacing: If True, tabs and newlines will not be escaped.
    """

    if not isinstance(data, bytes):
        raise ValueError(f"data must be bytes, but is {data.__class__.__name__}")
    # We always insert a double-quote here so that we get a single-quoted string back
    # https://stackoverflow.com/questions/29019340/why-does-python-use-different-quotes-for-representing-strings-depending-on-their
    ret = repr(b'"' + data).lstrip("b")[2:-1]
    if not escape_single_quotes:
        ret = re.sub(r"(?<!\\)(\\\\)*\\'", lambda m: (m.group(1) or "") + "'", ret)
    if keep_spacing:
        ret = re.sub(
            r"(?<!\\)(\\\\)*\\([nrt])",
            lambda m: (m.group(1) or "") + dict(n="\n", r="\r", t="\t")[m.group(2)],
            ret,
        )
    return ret

class Siri:
    silent=True
    zlib_obj=None
    posn=0 

    def tcp_message(self, flow: tcp.TCPFlow):
        message = flow.messages[-1]
        try:
            #print(message.content)
            if self.zlib_obj is None:
                unzipped = message.content
            else:
                try:
                    unzipped = self.zlib_obj.decompress(message.content)
                except:
                    try:
                        print("***ERROR zlib failed, re-trying from start")
                        self.zlib_obj=zlib.decompressobj()
                        unzipped = self.zlib_obj.decompress(message.content)
                    except Exception as e:
                        print("***ERROR zlib failed again ", e)
                        unzipped=[]
                        self.zlib_obj=zlib.decompressobj()
            if self.posn>0:
                # print trailing bytes from last packet
                print("posn=",self.posn)
                print(unzipped[:self.posn])
            while self.posn < len(unzipped):
                if (unzipped[self.posn]==170) and (unzipped[self.posn+1]==204) and (unzipped[self.posn+2]==238):
                    #dataForStreamHeaderWithCompressionType
                    # 4 bytes.  last byte is compression type, assume zlib here
                    # start decompressing after this. 
                    print("stream start header received")
                    self.zlib_obj=zlib.decompressobj()
                    unzipped = self.zlib_obj.decompress(message.content[self.posn+4:])
                    self.posn=0
                    continue
                if self.zlib_obj is None:
                    #just print out the raw text
                    print(chr(unzipped[self.posn]), end='')
                    self.posn=self.posn+1
                    continue

                # stream mode (self.zlib_obj is not None), so try to parse out the packets
                # pkt header is: char, 0, 0, 2 bytes length
                #print(unzipped[self.posn],unzipped[self.posn+1],unzipped[self.posn+2],unzipped[self.posn+3],unzipped[self.posn+4])

                if (unzipped[self.posn]==2) and (unzipped[self.posn+1]==0) and (unzipped[self.posn+2]==0):
                    #dataForObject
                    print("plist packet:")
                    pktlength =unzipped[self.posn+3]*256+unzipped[self.posn+4] # big-endian
                    pkt=unzipped[self.posn+5:self.posn+5+pktlength]
                    #print(strutils.bytes_to_escaped_str(pkt))
                    try:
                        print(plistlib.loads(pkt))
                    except Exception as e:
                        print("***plist ERROR ",e)  
                        print(strutils.bytes_to_escaped_str(pkt)) 
                        print(self.posn+5+pktlength,len(unzipped))
                    #print('raw plist')
                    #print(strutils.bytes_to_escaped_str(pkt))
                    self.posn=self.posn+5+pktlength
                elif (unzipped[self.posn]==0) and (unzipped[self.posn+1]==0) and (unzipped[self.posn+2]==0):
                    #dataForNop.  Always length 5
                    print("nop packet")
                    pktlength = unzipped[self.posn+3]*256+unzipped[self.posn+4]
                    if pktlength !=1:
                        print("***WARNING nop pkt len!=1")
                    pkt=unzipped[self.posn+4:self.posn+5]
                    #print(strutils.bytes_to_escaped_str(pkt))
                    self.posn=self.posn+5
                elif (unzipped[self.posn]==3) and (unzipped[self.posn+1]==0) and (unzipped[self.posn+2]==0):
                    #dataForPing.  Always length 5
                    print("ping packet")
                    pktlength = unzipped[self.posn+3]*256+unzipped[self.posn+4]
                    if pktlength !=1:
                        print("***WARNING ping pkt len!=1")
                        print(strutils.bytes_to_escaped_str(unzipped[self.posn:self.posn+5])) 
                    pkt=unzipped[self.posn+4:self.posn+4+pktlength]
                    #print(strutils.bytes_to_escaped_str(pkt))
                    self.posn=self.posn+5
                elif (unzipped[self.posn]==4) and (unzipped[self.posn+1]==0) and (unzipped[self.posn+2]==0):
                    #dataForPong.  Always length 5
                    print("pong packet")
                    pktlength = unzipped[self.posn+3]*256+unzipped[self.posn+4]
                    if pktlength !=1:
                        print("***WARNING pong pkt len!=1")
                        print(strutils.bytes_to_escaped_str(unzipped[self.posn:self.posn+5])) 
                    pkt=unzipped[self.posn+4:self.posn+4+pktlength]
                    #print(strutils.bytes_to_escaped_str(pkt))
                    self.posn=self.posn+5
                elif (unzipped[self.posn]==7) and (unzipped[self.posn+1]==0) and (unzipped[self.posn+2]==0):
                    #dataForSpeechPacket
                    #<5 byte header><strlen>UTF8string<#opus pkts><opus pkt len><pkt>...
                    print("speech packet:")
                    pktlength = unzipped[self.posn+3]*256+unzipped[self.posn+4]
                    pkt=unzipped[self.posn+5:self.posn+5+pktlength]
                    #print(unzipped[self.posn:self.posn+6])
                    strlen=pkt[0]
                    print(pkt[1:1+strlen]) #refId
                    pkt=pkt[1+strlen:] 
                    print(strutils.bytes_to_escaped_str(pkt))
                    #print(pkt[0]*256+pkt[1])
                    pkt=pkt[2:]
                    numOpusPkts=pkt[0]*256+pkt[1]
                    #print(numOpusPkts)
                    pkt=pkt[2:]
                    #print(strutils.bytes_to_escaped_str(pkt))
                    for i in range(numOpusPkts):
                        try:
                            # this loop might fail if speech packet is split across more than one chunk
                            # - just fail for now
                            opusPktLen=pkt[0]*256+pkt[1]
                            print(opusPktLen)
                            opuspkt=pkt[2:2+opusPktLen]
                            #print(strutils.bytes_to_escaped_str(opuspkt))
                            #decoder=OpusDecoder()
                            #decoder.set_sampling_frequency(48000)
                            #decoder.set_channels(1)
                            #pcm = decoder.decode(bytearray(opuspkt))
                            #if not self.silent:
                            #    self.stream.write(pcm.tobytes())
                        except Exception as e:
                            print("***ERROR opus pkt ",e)
                            #print(strutils.bytes_to_escaped_str(self.speech_buf[refId]))
                        pkt=pkt[2+opusPktLen:]
                    self.posn=self.posn+5+pktlength
                elif (unzipped[self.posn]==170) and (unzipped[self.posn+1]==204) and (unzipped[self.posn+2]==238):
                    #dataForStreamEnd
                    # 5 bytes FF 00 00 00 00
                    print("stream end")
                    self.posn=self.posn+5
                    self.zlib_obj=None # stop compressed stream, go back to text
                    return
                else:
                    print('***ERROR unknown pkt ',unzipped[self.posn+3], unzipped[self.posn+4])
                    length = unzipped[self.posn+4]+unzipped[self.posn+3]*256
                    print(length)
                    print(strutils.bytes_to_escaped_str(unzipped[self.posn:self.posn+5+length]))
                    self.posn = self.posn+5+length
                    if self.posn>len(unzipped):
                        print("**overrun")
                        print(self.posn,len(unzipped))
                        #self.posn=0
                        #break
                    #break
            #print('***finished ',self.posn,len(unzipped),self.posn-len(unzipped))
            self.posn = self.posn-len(unzipped) # trailing bytes might be part of next pkt         
        except Exception as e:
            print("***ERROR ",e)
            print(traceback.format_exc())
            #print("uncompressed data:")
            #print(strutils.bytes_to_escaped_str(unzipped[self.posn:]))
            self.posn = 0

class decodeSiri:
    siri_to=Siri()
    siri_from=Siri()

    def tcp_message(self, flow: tcp.TCPFlow):
        message = flow.messages[-1]
        if message.from_client:
             arrow=" -> "
        else:
            arrow=" <- "
        print(flow.client_conn.peername[0]+":"+str(flow.client_conn.peername[1])+arrow+flow.server_conn.peername[0]+":"+str(flow.server_conn.peername[1]))
        if message.from_client:
            self.siri_from.tcp_message(flow)
        else:
            self.siri_to.tcp_message(flow)


class PrintTrace:

    start_timestamp = -1
    connection_count = 0
    decodeSiri=decodeSiri()

    def tcp_message(self, flow: tcp.TCPFlow):
        if '108.128.193.124' in flow.client_conn.peername[0] or '108.128.193.124' in flow.server_conn.peername[0]:
            # guzzoni
            self.decodeSiri.tcp_message(flow)
        else:
            # just dump the raw data
            message = flow.messages[-1]
            if message.from_client:
                arrow=" -> "
            else:
                arrow=" <- "
            print(flow.client_conn.peername[0]+":"+str(flow.client_conn.peername[1])+arrow+flow.server_conn.peername[0]+":"+str(flow.server_conn.peername[1]))
            print("content=",strutils.bytes_to_escaped_str(message.content))

    def load(self, loader):
        # add new command line options for start and end time of dump
        loader.add_option(
            name="expt_starttime",
            typespec=int,
            default=-1,
            help="Add a start timestamp, ignore earlier connections")
        loader.add_option(
            name="expt_endtime",
            typespec=int,
            default=-1,
            help="Add a end timestamp, ignore later connections")
        # add command line option to only process a specified number of connections"
        loader.add_option(
            name="num_connections",
            typespec=int,
            default=-1,
            help="Number of connections to process")
        # add command line option to set an experiment name"
        loader.add_option(
            name="expt_name",
            typespec=str,
            default="",
            help="experiment name to use")

    def request(self, flow:http.HTTPFlow):
        if ctx.options.num_connections and ctx.options.num_connections>0:
            if self.connection_count >= ctx.options.num_connections:
                ctx.master.shutdown() # quit mitmdump, doesn't seem to work?
                quit() # force quit, works but generates error trace
        self.connection_count = self.connection_count+1

    def hash_long_string(self,string_):
        if len(string_)>128:
            m = hashlib.sha256()
            m.update(string_.encode('utf8'))
            return "sha256#"+m.hexdigest()
        else:
            return string_

    def response(self, flow:http.HTTPFlow):
        
        # check command line options for start and end time of dump
        if ctx.options.expt_starttime and ctx.options.expt_starttime>0:
            #print("start",flow.request.timestamp_start,ctx.options.expt_starttime)
            if flow.request.timestamp_start < ctx.options.expt_starttime:
                return
        if ctx.options.expt_endtime and ctx.options.expt_endtime>0:
            #print("end",flow.request.timestamp_start,ctx.options.expt_endtime)
            if flow.request.timestamp_start > ctx.options.expt_endtime:
                return

        print("\ntimestamp %s (%s UTC)"%(flow.request.timestamp_start, datetime.datetime.fromtimestamp(flow.request.timestamp_start,datetime.timezone.utc)))
        print("%s %s" % (flow.request.method, flow.request.pretty_url))
        url = flow.request.pretty_url
        request_content_sum = printRequest(url,flow.request) 
        printResponse(url,flow.response) 
        useragent="-"
        if 'User-Agent' in flow.request.headers:
            useragent=f"User-Agent='{flow.request.headers['User-Agent']}'"
        headers=""
        # 'x-apple-actionsignature' hash of message body, see https://objects.githubusercontent.com/github-production-repository-file-5c1aeb/96335883/9372019?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAVCODYLSA53PQK4ZA%2F20260206%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20260206T221234Z&X-Amz-Expires=300&X-Amz-Signature=5bdc95584315a6b35b66613472a08f5f5d8888fa07fbe580ad4ea6bef701f693&X-Amz-SignedHeaders=host&response-content-disposition=attachment%3Bfilename%3Ddaap-paper.pdf&response-content-type=application%2Fpdf
        # 'X-Apple-I-MD' one time passwd
        interesting_headers=['X-Apple-I-MD-M','X-Apple-I-MD-RINFO','x-apple-seid',
            'X-Mme-Device-Id','x-jmet-deviceid','X-Apple-I-SRL-NO','X-Apple-I-Baa-S','x-apple-baa-signature',
            'x-apple-baa-certs','baa-certs','authorization','X-Apple-Baa','x-apple-uuid',
            'maps-auth-token','siri-absinthe-token-bin']
        for h in interesting_headers:
            if h in flow.request.headers:
                val = self.hash_long_string(flow.request.headers[h])
                headers=headers+f'{h}={val}~'
            elif h.lower() in flow.request.headers:
                headers=headers+f'{h}={self.hash_long_string(flow.request.headers[h.lower()])} '
        if 'cookie' in flow.request.headers:
            # list each cookie separately
            parts = flow.request.headers['cookie'].split(" ")
            for p in parts:
                if len(p) > 0:
                    headers=headers+f'cookie={p}~'
        # check the other headers too:
        boring_headers_=['Accept','Accept-Language','Accept-Encoding','Date','Connection','Content-Type','Content-Length',
                        'User-Agent','Host','x-apple-client-application','x-apple-store-front','x-apple-tz','x-apple-canary-id','maps-tile-x','X-Apple-I-Client-Time','x-apple-i-client-time',
                        'x-apple-operation-id','X-Apple-Request-UUID','X-Apple-Download-Identifier','x-apple-i-locale',
                        'X-Apple-I-Client-Time','if-none-match','x-apple-destination','Range','siri-osprey-trace-id',
                        'x-apple-digest','x-cloudkit-duetpreclearedmode','x-apple-operation-group-id','x-os-version','x-apple-date',
                        'content-encoding','x-apple-signature','x-os-train','x-apple-device-model','x-apple-mmcs-dataclass',
                        'x-apple-app-store-client-request-id','x-cloudkit-containerid','x-product-release','X-Apple-I-Locale',
                        'x-apple-i-timezone','retry-attempt','x-apple-expires','x-apple-ct-client-time','X-Mme-Client-Info',
                        'X-Apple-HMAC-Sent-Timestamp','x-hardware-model','locale','x-apple-cc','grpc-encoding','X-Apple-Object-ID',
                        'grpc-accept-encoding','bundleID','maps-tile-style','x-cloudkit-databasescope','X-Apple-Client-App-Name','x-apple-c2-metric-triggers',
                        'cache-control','x-cloudkit-bundleid','x-cloudkit-environment','x-apple-connection-type','x-protocol-version',
                        'maps-tile-reason','x-apple-languages','x-apple-seed','X-MMe-Country','x-apple-ct-region-identifier','x-apple-en-os-version',
                        'x-mask-user-tier','x-mask-fetch-reason','client-region','x-mask-client-info','x-rtc-sender',
                        'if-modified-since','maps-tile-z','x-apple-whitelisted-app-signature','x-task-id','x-gk-production-signed',
                        'x-apple-mme-owner','X-tilekey','device','asdversion','x-routing','siri-osprey','X-Apple-Diagnostic-Reason',
                        'x-request-id','x-apple-mmcs-container-size','X-Apple-Download-Reason','X-Apple-I-Payload-Hash','timestamp','x-apple-subscriptions',
                        'Referer','X-Apple-Content-SHA256','maps-tile-y','os_Version','storefront','x-tasking-requested','x-apple-client-versions',
                        'x-cloudkit-businesschat-queryname','x-cloudkit-container','X-Client-Request-ID','X-Apple-Find-API-Ver',
                        'x-apple-partner','Upgrade-Insecure-Requests','X-FMF-Model-Version','siri-device-auth-version','origin',
                        'x-apple-soc-type','x-rtc-client-name','X-Apple-I-TimeZone-Offset','x-http-method-override','x-apple-partner',
                        'X-Apple-I-SKU-Country','te','x-apple-requestid','X-Apple-HMAC-Secret-Version','x-apple-content-partition','x-apple-ckappid',
                        'limitAdTracking','X-Apple-Device-Region','x-request-timestamp','X-Apple-Client-Info','x-target-audience','X-Apple-AuthScheme',
                        'x-apple-ui-scale','x-cloudkit-zones','x-rtc-service-name','X-MMe-Timezone','x-cloudkit-businesslink-queryname','x-rtc-service-name',
                        'x-apple-application','X-Apple-Realm-Support','grpc-timeout','x-msg-priority','x-rtc-internal-build','x-trial-zoneid']
        boring_headers=[]
        for h in boring_headers_:
            boring_headers.append(h.lower())
        for h in flow.request.headers:
            if (h in interesting_headers) or (h.lower()=='cookie') or (h.lower() in boring_headers):
                continue
            val = self.hash_long_string(flow.request.headers[h])
            headers=headers+f'{h}={val}~'
        print('+++REQUEST ', flow.request.pretty_url, request_content_sum, flow.request.timestamp_start)
        print('+++REQHEADERS ', flow.request.pretty_url, '€', useragent, '€', headers)
 

#tell mitmproxy to use PrintTrace() class as an addon, this way we can use "-s decoding_helpers.py" as mitmdump option and things just work
addons = [PrintTrace()]


