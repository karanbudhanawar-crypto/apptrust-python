from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from google_play_scraper import app as gplay_app, search, reviews, Sort
from google_play_scraper import collection as gp_collection
import os, re, json, threading
from dotenv import load_dotenv

load_dotenv()
server = Flask(__name__, static_folder='public', static_url_path='')
CORS(server)

COUNTRY = os.getenv('PLAY_STORE_COUNTRY', 'in')
LANG    = os.getenv('PLAY_STORE_LANG', 'en')
MAX_REV = int(os.getenv('MAX_REVIEWS', 100))
_cache  = {}

# ── SENTIMENT ─────────────────────────────────────────────────────────────────
try:
    from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer
    _sia = SentimentIntensityAnalyzer()
    def sentiment(text): return _sia.polarity_scores(text)['compound']
except:
    POS = ['good','great','excellent','love','best','amazing','perfect','awesome']
    NEG = ['bad','terrible','awful','hate','worst','horrible','broken','scam']
    def sentiment(text):
        t = text.lower()
        p = sum(1 for w in POS if w in t)
        n = sum(1 for w in NEG if w in t)
        return (p-n)/max(p+n,1)

# ── FAKE REVIEW DETECTION ─────────────────────────────────────────────────────
def detect_fake(rv_list):
    if not rv_list:
        return {'fakePct':0,'signals':['No reviews to analyse']}
    fake, signals, tmap = 0, [], {}
    for r in rv_list:
        k = (r.get('content','') or '').lower().strip()[:40]
        if len(k)>5: tmap[k] = tmap.get(k,0)+1
    dups = sum(v for v in tmap.values() if v>1)
    if dups:
        fake += dups
        signals.append(f'{dups} duplicate reviews found')
    short5 = [r for r in rv_list if r.get('score')==5 and len((r.get('content','') or '').split())<=3]
    if len(short5) > len(rv_list)*.2:
        fake += len(short5)
        signals.append(f'{len(short5)} suspiciously short 5-star reviews')
    exc = [r for r in rv_list if (r.get('content','') or '').count('!')>=3]
    if len(exc) > len(rv_list)*.15:
        fake += len(exc)//2
        signals.append(f'Abnormal punctuation in {len(exc)} reviews')
    five_pct = len([r for r in rv_list if r.get('score')==5]) / max(len(rv_list),1)
    if five_pct > .9 and len(rv_list)>20:
        fake += len(rv_list)//5
        signals.append(f'Unnaturally high 5-star ratio ({five_pct*100:.0f}%)')
    if not signals:
        signals.append('No significant bot patterns detected')
    return {'fakePct': min(95, round(fake/max(len(rv_list),1)*100)), 'signals': signals}

# ── TRUST SCORE ───────────────────────────────────────────────────────────────
def trust_score(app_data, rv_list, avg_pol):
    score, reasons = 10, []
    rating = float(app_data.get('score') or 0)
    if rating<2.0:   score-=3; reasons.append(f'⚠ Very low rating: {rating:.1f} stars')
    elif rating<3.0: score-=2; reasons.append(f'⚠ Low rating: {rating:.1f} stars')
    elif rating<3.8: score-=1; reasons.append(f'Below average rating: {rating:.1f} stars')
    else:            reasons.append(f'✓ Good rating: {rating:.1f} stars')
    rc = int(app_data.get('ratings') or 0)
    if rc<100:   score-=2; reasons.append(f'⚠ Very few ratings ({rc})')
    elif rc<1000:score-=1; reasons.append(f'Limited ratings: {rc:,}')
    else:        reasons.append(f'✓ {rc:,} ratings — good credibility')
    if avg_pol<-.3:  score-=3; reasons.append(f'⚠ Strongly negative sentiment ({avg_pol:.2f})')
    elif avg_pol<0:  score-=2; reasons.append(f'⚠ Negative sentiment: {avg_pol:.2f}')
    elif avg_pol<.2: score-=1; reasons.append(f'Mixed sentiment: {avg_pol:.2f}')
    else:            reasons.append(f'✓ Positive sentiment: {avg_pol:.2f}')
    fake = detect_fake(rv_list)
    if fake['fakePct']>60:   score-=2; reasons.append(f'⚠ High fake reviews: ~{fake["fakePct"]}%')
    elif fake['fakePct']>30: score-=1; reasons.append(f'⚠ Moderate fake reviews: ~{fake["fakePct"]}%')
    else:                    reasons.append(f'✓ Low fake review probability: ~{fake["fakePct"]}%')
    inst = re.sub(r'[^0-9]','', str(app_data.get('installs','0')) or '0')
    if int(inst or 0)<1000:       score-=1; reasons.append(f'⚠ Very low installs')
    elif int(inst or 0)>=1000000: reasons.append(f'✓ High install count: {app_data.get("installs","")}')
    else:                         reasons.append(f'Moderate install count: {app_data.get("installs","")}')
    score = max(1, min(10, score))
    label = 'Safe' if score>=7 else 'Suspicious' if score>=4 else 'Scam'
    return {'score':score,'label':label,'reasons':reasons,'fake':fake}

# ── PERMISSIONS ───────────────────────────────────────────────────────────────
PERM_MAP = {
    'CAMERA':                {'icon':'📷','name':'Camera','risk':'med'},
    'RECORD_AUDIO':          {'icon':'🎤','name':'Microphone','risk':'med'},
    'ACCESS_FINE_LOCATION':  {'icon':'📍','name':'Precise Location','risk':'high'},
    'ACCESS_COARSE_LOCATION':{'icon':'📍','name':'Location','risk':'med'},
    'READ_CONTACTS':         {'icon':'📇','name':'Read Contacts','risk':'high'},
    'WRITE_CONTACTS':        {'icon':'📇','name':'Write Contacts','risk':'high'},
    'READ_SMS':              {'icon':'💬','name':'Read SMS','risk':'high'},
    'SEND_SMS':              {'icon':'💬','name':'Send SMS','risk':'high'},
    'READ_CALL_LOG':         {'icon':'📞','name':'Call Logs','risk':'high'},
    'READ_EXTERNAL_STORAGE': {'icon':'💾','name':'Storage Read','risk':'low'},
    'WRITE_EXTERNAL_STORAGE':{'icon':'💾','name':'Storage Write','risk':'med'},
    'INTERNET':              {'icon':'📶','name':'Internet','risk':'low'},
    'RECEIVE_BOOT_COMPLETED':{'icon':'🔔','name':'Auto-Start','risk':'med'},
    'BILLING':               {'icon':'💳','name':'In-App Purchases','risk':'high'},
}
RISK_LBL = {'high':'High','med':'Medium','low':'Low'}

def fmt_perms(raw):
    seen, out = set(), []
    for p in (raw or []):
        k = next((x for x in PERM_MAP if x in (p or '').upper()), None)
        if k and k not in seen:
            seen.add(k)
            m = PERM_MAP[k]
            out.append({'icon':m['icon'],'name':m['name'],'risk':m['risk'],'label':RISK_LBL[m['risk']]})
    return out[:8]

def fmt_reviews(raw):
    out = []
    for r in raw[:5]:
        txt = r.get('content','') or ''
        s = sentiment(txt)
        bot = len(txt.split())<=4 and r.get('score')==5 and txt.count('!')>=2
        if bot:      lbl,col = 'Suspicious','#9b59b6'
        elif s>.05:  lbl,col = 'Positive','#1dbd7a'
        elif s<-.05: lbl,col = 'Negative','#e74c3c'
        else:        lbl,col = 'Neutral','#3498db'
        out.append({'score':r.get('score',0),'text':txt or 'No review text',
                    'sentiment':lbl,'color':col,'bot':bot,'author':r.get('userName','Anonymous')})
    return out

def fmt_app(r):
    """Format a scraped app for frontend."""
    return {
        'appId':     r.get('appId',''),
        'title':     r.get('title',''),
        'icon':      r.get('icon',''),
        'score':     r.get('score'),
        'developer': r.get('developer',''),
        'summary':   r.get('summary',''),
        'installs':  r.get('installs',''),
        'genre':     r.get('genre',''),
    }

# ── ICON PROXY — serves Google Play icons bypassing CORS ─────────────────────
import requests as _req

def _fetch_icon(url):
    """Fetch icon bytes from Google CDN with proper headers."""
    ck = f'iconbytes_{url}'
    if ck in _cache:
        return _cache[ck]
    try:
        r = _req.get(url, timeout=8, headers={
            'User-Agent': 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36',
            'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://play.google.com/',
            'Origin': 'https://play.google.com',
        })
        if r.status_code == 200:
            data = {'bytes': r.content, 'mime': r.headers.get('Content-Type','image/png')}
            _cache[ck] = data
            return data
    except Exception as e:
        print(f'Icon fetch error: {e}')
    return None

# ── ROUTES ────────────────────────────────────────────────────────────────────
@server.route('/')
def index():
    return send_from_directory('public','index.html')

@server.route('/proxy-icon')
def proxy_icon():
    url = request.args.get('url','').strip()
    if not url or 'googleusercontent.com' not in url:
        return '', 400
    data = _fetch_icon(url)
    if data:
        resp = Response(data['bytes'], mimetype=data['mime'])
        resp.headers['Cache-Control'] = 'public, max-age=604800'  # 7 days
        resp.headers['Access-Control-Allow-Origin'] = '*'
        return resp
    return '', 404

@server.route('/category', methods=['POST'])
def category_route():
    body = request.get_json() or {}
    cat = body.get('category','SOCIAL')
    col = body.get('collection','TOP_FREE')
    count = int(body.get('count', 30))
    ck = f'cat_{cat}_{col}_{count}'
    if ck in _cache:
        return jsonify({'success':True,'apps':_cache[ck]})
    try:
        res = gp_collection(col, category=cat, country=COUNTRY, lang=LANG, count=count)
        apps = [fmt_app(r) for r in res]
        _cache[ck] = apps
        return jsonify({'success':True,'apps':apps})
    except Exception as e:
        print(f'Category error: {e}')
        return jsonify({'success':False,'apps':[],'error':str(e)})

@server.route('/search', methods=['POST'])
def search_route():
    q = (request.get_json() or {}).get('query','').strip()
    if len(q)<2:
        return jsonify({'success':False,'results':[]})
    ck = f'search_{q.lower()}'
    if ck in _cache:
        return jsonify({'success':True,'results':_cache[ck]})
    try:
        res = search(q, n_hits=10, country=COUNTRY, lang=LANG)
        fmt = [fmt_app(r) for r in res]
        _cache[ck] = fmt
        return jsonify({'success':True,'results':fmt})
    except Exception as e:
        print(f'Search error: {e}')
        return jsonify({'success':False,'results':[],'error':str(e)})

@server.route('/analyze', methods=['POST'])
def analyze_route():
    pkg = (request.get_json() or {}).get('package_id','').strip()
    if not pkg:
        return jsonify({'success':False,'error':'package_id required'})
    ck = f'analyze_{pkg}'
    if ck in _cache:
        return jsonify(_cache[ck])
    try:
        print(f'Analyzing: {pkg}')
        ad = gplay_app(pkg, country=COUNTRY, lang=LANG)
        raw_rv = []
        try:
            raw_rv, _ = reviews(pkg, country=COUNTRY, lang=LANG, sort=Sort.NEWEST, count=MAX_REV)
        except Exception as e:
            print(f'Reviews warning: {e}')
        pol = 0
        for r in raw_rv:
            txt = r.get('content','') or ''
            if txt: pol += sentiment(txt)/max(len(txt.split()),1)
        avg_pol = round(pol/max(len(raw_rv),1),2)
        ts = trust_score(ad, raw_rv, avg_pol)
        perms = fmt_perms(ad.get('permissions',[]))
        fmtd_rv = fmt_reviews(raw_rv)
        high_risk = len([p for p in perms if p['risk']=='high'])
        perm_pct = min(98, high_risk*14+6)
        resp = {
            'success':True,
            'title':         ad.get('title',''),
            'icon':          ad.get('icon',''),
            'package_id':    ad.get('appId', pkg),
            'developer':     ad.get('developer',''),
            'rating':        str(round(float(ad.get('score') or 0),1)),
            'installs':      ad.get('installs','Unknown'),
            'reviews_count': f"{int(ad.get('ratings') or 0):,}",
            'version':       ad.get('version','N/A'),
            'updated':       str(ad.get('updated','N/A')),
            'genre':         ad.get('genre','App'),
            'play_store_url':f"https://play.google.com/store/apps/details?id={pkg}",
            'trust_score':   ts['score'],
            'safety_score':  ts['score']*10,
            'label':         ts['label'],
            'avg_polarity':  str(avg_pol),
            'reasons':       ts['reasons'],
            'permissions':   perms,
            'fake_pct':      ts['fake']['fakePct'],
            'fake_signals':  ts['fake']['signals'],
            'perm_pct':      perm_pct,
            'dev_score':     8 if ts['score']>=7 else 5 if ts['score']>=4 else 2,
            'dev_pct':       (8 if ts['score']>=7 else 5 if ts['score']>=4 else 2)*10,
            'reviews':       fmtd_rv,
            'sentiment_pct': min(100,max(0,round((avg_pol+1)*50))),
        }
        _cache[ck] = resp
        print(f"Done: {ad.get('title')} → {ts['label']} ({ts['score']}/10)")
        return jsonify(resp)
    except Exception as e:
        print(f'Analyze error: {e}')
        return jsonify({'success':False,'error':'App not found or Play Store unavailable.'})

if __name__=='__main__':
    port = int(os.getenv('PORT',5000))
    print(f'\n✅ AppTrust Python Backend → http://localhost:{port}')
    print(f'   Country: {COUNTRY.upper()} | Max Reviews: {MAX_REV}\n')
    server.run(host='0.0.0.0', port=port, debug=False)
