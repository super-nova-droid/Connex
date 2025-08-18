#!/usr/bin/env python3
"""Test calendar endpoint availability"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from app import app
    from flask import url_for
    
    with app.app_context():
        try:
            calendar_url = url_for('calendar')
            print(f"✅ Calendar endpoint works: {calendar_url}")
        except Exception as e:
            print(f"❌ Calendar endpoint error: {e}")
        
        try:
            mfa_url = url_for('mfa')
            print(f"✅ MFA endpoint works: {mfa_url}")
        except Exception as e:
            print(f"❌ MFA endpoint error: {e}")
            
    print("🎉 Route test completed!")
    
except Exception as e:
    print(f"💥 Import error: {e}")
