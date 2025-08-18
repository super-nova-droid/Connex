#!/usr/bin/env python3
"""
Quick test to verify the calendar route is registered
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app import app

def test_calendar_route():
    with app.app_context():
        # Test if calendar route is available
        routes = []
        for rule in app.url_map.iter_rules():
            if 'calendar' in rule.rule or 'mfa' in rule.rule:
                routes.append(f"{rule.rule} -> {rule.endpoint} (methods: {list(rule.methods)})")
        
        print("🔍 Calendar/MFA routes found:")
        for route in routes:
            print(f"  ✅ {route}")
        
        if not routes:
            print("  ❌ No calendar or mfa routes found!")
            return False
        
        # Test url_for calendar
        try:
            from flask import url_for
            calendar_url = url_for('mfa')  # The function name is 'mfa'
            print(f"  ✅ Calendar URL can be built: {calendar_url}")
            return True
        except Exception as e:
            print(f"  ❌ Error building calendar URL: {e}")
            return False

if __name__ == "__main__":
    print("Testing calendar route registration...")
    success = test_calendar_route()
    if success:
        print("🎉 Calendar route test PASSED!")
    else:
        print("💥 Calendar route test FAILED!")
