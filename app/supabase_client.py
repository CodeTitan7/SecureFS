from supabase import create_client
import os
from dotenv import load_dotenv

load_dotenv()

url = os.getenv("SUPABASE_URL")
key = os.getenv("SUPABASE_KEY")

supabase = create_client(url, key)


def upload_file(file_path, file_name):
    with open(file_path, "rb") as f:
        supabase.storage.from_("files").upload(file_name, f)

def download_file(file_name, save_path):
    res = supabase.storage.from_("files").download(file_name)
    with open(save_path, "wb") as f:
        f.write(res)


def save_metadata(enc_filename, original_filename, client_public_key, user_id):
    supabase.table("file_metadata").insert({
        "enc_filename": enc_filename,
        "original_filename": original_filename,
        "client_public_key": client_public_key,
        "user_id": user_id
    }).execute()

def get_metadata(enc_filename):
    res = supabase.table("file_metadata").select("*").eq("enc_filename", enc_filename).single().execute()
    return res.data

def get_user_files(user_id):
    res = supabase.table("file_metadata").select("enc_filename").eq("user_id", user_id).execute()
    return [row["enc_filename"] for row in res.data]


def save_share_token(enc_filename, share_token, password_hash, expires_at):
    supabase.table("file_metadata").update({
        "share_token": share_token,
        "password_hash": password_hash,
        "expires_at": expires_at
    }).eq("enc_filename", enc_filename).execute()

def get_metadata_by_token(share_token):
    res = supabase.table("file_metadata").select("*").eq("share_token", share_token).single().execute()
    return res.data


def verify_token(token: str):
    # Verify Supabase JWT and return user dict or None
    try:
        user = supabase.auth.get_user(token)
        return user.user
    except Exception:
        return None