"""User-isolated Ollama chat; deliberately no command execution or OpenClaw bridge."""
import json
import time
import threading
from urllib.request import Request, urlopen
from access_hub_next import models, rbac

MAX_PROMPT = 6000
MAX_CONTEXT = 30000
INFERENCE_SLOT = threading.BoundedSemaphore(1)


def check_chat(con, user_id, tag):
    if not rbac.has_permission(con, user_id, 'agent.chat'):
        raise PermissionError('Sohbet yetkiniz yok')
    if tag not in {m['tag'] for m in models.allowed_models(con, user_id)}:
        raise PermissionError('Bu modele erişiminiz yok')


def messages_for(con, user_id, conversation_id):
    row = con.execute('SELECT id FROM nova_conversations WHERE id=? AND user_id=?', (conversation_id,user_id)).fetchone()
    if row is None:
        raise ValueError('Konuşma bulunamadı')
    return [dict(zip(('role','content'),row)) for row in con.execute('SELECT role,content FROM (SELECT id,role,content FROM nova_messages WHERE conversation_id=? ORDER BY id DESC LIMIT 20) ORDER BY id', (conversation_id,))]


def request_ollama(tag, messages, system_prompt):
    items = ([{'role':'system','content':system_prompt}] if system_prompt else []) + messages
    body = json.dumps({'model':tag,'messages':items,'stream':False}, ensure_ascii=False).encode('utf-8')
    req = Request('http://127.0.0.1:11434/api/chat', data=body, headers={'Content-Type':'application/json'}, method='POST')
    if not INFERENCE_SLOT.acquire(blocking=False):
        raise BlockingIOError('Model şu anda başka bir istekle meşgul')
    try:
        with urlopen(req, timeout=120) as response:
            raw = response.read(2_000_001)
    finally:
        INFERENCE_SLOT.release()
    if len(raw)>2_000_000:
        raise ValueError('Model yanıtı çok büyük')
    result = json.loads(raw)
    text = result.get('message',{}).get('content')
    if not isinstance(text, str) or not text.strip() or len(text)>100_000:
        raise ValueError('Model geçerli bir yanıt döndürmedi')
    return text


def prepare(con, user_id, tag, prompt, conversation_id):
    if not isinstance(tag,str) or not isinstance(prompt,str) or not prompt.strip() or len(prompt)>MAX_PROMPT:
        raise ValueError('Mesaj veya model geçersiz')
    if conversation_id is not None and (type(conversation_id) is not int or conversation_id <= 0):
        raise ValueError('Konuşma kimliği geçersiz')
    check_chat(con,user_id,tag)
    if conversation_id is not None and not rbac.has_permission(con,user_id,'agent.history'):
        raise PermissionError('Konuşma geçmişi yetkiniz yok')
    history = messages_for(con,user_id,conversation_id) if conversation_id is not None else []
    bounded, used = [], len(prompt.strip())
    for item in reversed(history):
        size = len(item['content'])
        if used + size > MAX_CONTEXT:
            break
        bounded.append(item)
        used += size
    history = list(reversed(bounded))
    row = con.execute('SELECT system_prompt FROM nova_models WHERE tag=? AND active=1',(tag,)).fetchone()
    if not row: raise ValueError('Model bulunamadı')
    return history + [{'role':'user','content':prompt.strip()}], row[0]


def save(con, user_id, tag, prompt, answer, conversation_id):
    check_chat(con,user_id,tag)
    if not rbac.has_permission(con,user_id,'agent.history'):
        if conversation_id is not None:
            raise PermissionError('Konuşma geçmişi yetkiniz yok')
        return None
    if conversation_id is None:
        cur = con.execute('INSERT INTO nova_conversations(user_id,title,created_at) VALUES (?,?,?)',(user_id,prompt.strip()[:80],int(time.time())))
        conversation_id = int(cur.lastrowid)
    else:
        messages_for(con,user_id,conversation_id)
    con.executemany('INSERT INTO nova_messages(conversation_id,role,content,created_at) VALUES (?,?,?,?)',
                    [(conversation_id,'user',prompt.strip(),int(time.time())),(conversation_id,'assistant',answer,int(time.time()))])
    return conversation_id
