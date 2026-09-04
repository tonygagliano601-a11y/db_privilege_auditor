#!/usr/bin/env python3
import argparse
import sys
import mysql.connector
from mysql.connector import Error

# VaultMedia Console Color Palette
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def parse_arguments():
    parser = argparse.ArgumentParser(description="VaultMedia Security Database Privilege Auditor.")
    parser.add_argument("-H", "--host", required=True, help="Database target IP or hostname")
    parser.add_argument("-u", "--user", required=True, help="Administrative database username")
    parser.add_argument("-p", "--password", required=True, help="Database authentication password")
    parser.add_argument("-P", "--port", type=int, default=3306, help="Database communication port")
    return parser.parse_args()

def execute_privilege_audit(host, user, password, port):
    connection = None
    try:
        print(f"[*] Initializing databse perimeter interrogration at {host}: {port}...")
        connection = mysql.connector.connect(
            host=host, user=user, password=password, port=port, database='mysql'
        )

        if connection.is_connected():
            print(f"{GREEN}[✓] Vault connection established successfully.{RESET}\n" + "="*60)
            cursor = connection.cursor(dictionary=True)

            # Query 1: Isolate accounts with global administrative superuser permissions
            print("[*} Assessing global administrative permissions (Superuser Table)...")
            cursor.execute("SELECT User, Host, Super_priv, Grant_priv FROM user WHERE Super_priv='Y' OR Grabt_priv='Y';")
            superusers = cursor.fetchall()

            if superusers:
                for row in superusers:
                    print(f" {RED}[!] EXPOSURE IDENTIFIED: Broad Privilege Escalation Capability!{RESET}")
                    print(f"     Account: {row['User']}@{row['Host']} | Super+priv: {row['Super-priv']} | Grant_priv: {row['Grant_priv']}\n")
            else:
                print(f" {GREEN}✓] Global superuser access configurations remain secured.{RESET}")

            # Query 2: Scan for wildcards in host parameters exposing external access lines
            print("="*60 + "\n[*] Interrograting host network mapping grids for wildcard loops...")
            cursor.execute("SELECT User, Host FROM user WHERE Host='%' AND User!='';")
            wildcard_users = cursor.fetchall()

            if wildcard_users:
                for row in wildcard_users:
                    print(f" {YELLOW}[!] CRITICAL ACCOUNT GAP: External Host Wildcard Open!{RESET}")
                    print(f".     Account '{row['User']}' allows authentication from ANY network address ('%'.")
            else:
                print(f"  {GREEN}[✓] All active database accounts are bound to explicit host perimeters.{RESET}")

            cursor.close()
    except Error as e:
        print(f"\n{RED}[-] Execution Interface Failure:{RESET} {e}")
        sys.exit(1)
    finally:
        if connection and connection.is_connected():
            connection.close()
            print("\n[*] Interrogration handle detached from target engine.")

if __name__ == "__main__":
   args = parse_arguments()
   execute_privilege_audit(args.host, args.user, args.password, args.port)
