import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), "../.env"))

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY", "")

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8090")

NMAP_URL = "http://localhost:8001"
NIKTO_URL = "http://localhost:8002"
SQLMAP_URL = "http://localhost:8003"
FFUF_URL = "http://localhost:8004"
