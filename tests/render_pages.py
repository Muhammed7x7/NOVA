"""Render synthetic pages only; never uses server data."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from access_hub_next.app import page, ADMIN_BODY, PRIVATE_BODY, DEFAULT_SETTINGS

users = [{'id':1,'username':'admin','display_name':'Admin','role':'admin','active':True}]
dest = Path(sys.argv[1]); dest.mkdir(parents=True, exist_ok=True)
(dest/'admin.html').write_bytes(page('Yönetim Paneli', ADMIN_BODY, {'settings':DEFAULT_SETTINGS,'users':users}))
(dest/'private.html').write_bytes(page('Özel Alan', PRIVATE_BODY, {'user':users[0]}))
