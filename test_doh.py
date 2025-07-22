#!/usr/bin/env python3
"""
DoH (DNS over HTTPS) 테스트 스크립트
"""

import base64
import requests
import dns.message
import dns.name
import dns.rdatatype
import sys

def create_dns_query(domain, record_type='A'):
    """DNS 쿼리 메시지 생성"""
    query = dns.message.make_query(domain, record_type)
    return query.to_wire()

def test_doh_get(server_url, domain, record_type='A'):
    """DoH GET 요청 테스트"""
    print(f"\n🧪 Testing DoH GET: {domain} ({record_type})")
    
    # DNS 쿼리 생성
    query_data = create_dns_query(domain, record_type)
    print(f"📝 Query size: {len(query_data)} bytes")
    
    # Base64 인코딩
    query_b64 = base64.urlsafe_b64encode(query_data).decode().rstrip('=')
    print(f"📝 Base64 query: {query_b64[:50]}...")
    
    # DoH GET 요청
    url = f"{server_url}/dns-query"
    params = {'dns': query_b64}
    headers = {
        'Accept': 'application/dns-message',
        'User-Agent': 'rfdns-test/1.0'
    }
    
    try:
        response = requests.get(url, params=params, headers=headers, timeout=10, verify=False)
        print(f"✅ Response status: {response.status_code}")
        print(f"📝 Response size: {len(response.content)} bytes")
        
        if response.status_code == 200:
            # DNS 응답 파싱
            dns_response = dns.message.from_wire(response.content)
            print(f"📝 DNS ID: {dns_response.id}")
            print(f"📝 Answer count: {len(dns_response.answer)}")
            
            for answer in dns_response.answer:
                print(f"📝 Answer: {answer}")
        else:
            print(f"❌ Error response: {response.text}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")

def test_doh_post(server_url, domain, record_type='A'):
    """DoH POST 요청 테스트"""
    print(f"\n🧪 Testing DoH POST: {domain} ({record_type})")
    
    # DNS 쿼리 생성
    query_data = create_dns_query(domain, record_type)
    print(f"📝 Query size: {len(query_data)} bytes")
    
    # DoH POST 요청
    url = f"{server_url}/dns-query"
    headers = {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
        'User-Agent': 'rfdns-test/1.0'
    }
    
    try:
        response = requests.post(url, data=query_data, headers=headers, timeout=10, verify=False)
        print(f"✅ Response status: {response.status_code}")
        print(f"📝 Response size: {len(response.content)} bytes")
        
        if response.status_code == 200:
            # DNS 응답 파싱
            dns_response = dns.message.from_wire(response.content)
            print(f"📝 DNS ID: {dns_response.id}")
            print(f"📝 Answer count: {len(dns_response.answer)}")
            
            for answer in dns_response.answer:
                print(f"📝 Answer: {answer}")
        else:
            print(f"❌ Error response: {response.text}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")

def test_upstream(server_url, upstream, domain, record_type='A'):
    """업스트림 서버 테스트"""
    print(f"\n🧪 Testing upstream {upstream}: {domain} ({record_type})")
    
    # DNS 쿼리 생성
    query_data = create_dns_query(domain, record_type)
    print(f"📝 Query size: {len(query_data)} bytes")
    
    # DoH POST 요청 (업스트림)
    url = f"{server_url}/up/{upstream}"
    headers = {
        'Content-Type': 'application/dns-message',
        'Accept': 'application/dns-message',
        'User-Agent': 'rfdns-test/1.0'
    }
    
    try:
        response = requests.post(url, data=query_data, headers=headers, timeout=10, verify=False)
        print(f"✅ Response status: {response.status_code}")
        print(f"📝 Response size: {len(response.content)} bytes")
        
        if response.status_code == 200:
            # DNS 응답 파싱
            dns_response = dns.message.from_wire(response.content)
            print(f"📝 DNS ID: {dns_response.id}")
            print(f"📝 Answer count: {len(dns_response.answer)}")
            
            for answer in dns_response.answer:
                print(f"📝 Answer: {answer}")
        else:
            print(f"❌ Error response: {response.text}")
            
    except Exception as e:
        print(f"❌ Request failed: {e}")

def main():
    server_url = "https://localhost:443"
    
    if len(sys.argv) > 1:
        server_url = sys.argv[1]
    
    print(f"🚀 Testing DoH server: {server_url}")
    
    # 기본 테스트
    test_doh_get(server_url, "google.com")
    test_doh_post(server_url, "google.com")
    
    # 업스트림 테스트
    test_upstream(server_url, "cloudflare", "google.com")
    test_upstream(server_url, "google", "cloudflare.com")
    
    # 잘못된 쿼리 테스트 (빈 도메인)
    print(f"\n🧪 Testing empty query")
    try:
        url = f"{server_url}/dns-query"
        params = {'dns': ''}
        response = requests.get(url, params=params, timeout=10, verify=False)
        print(f"📝 Empty query response: {response.status_code}")
    except Exception as e:
        print(f"❌ Empty query test failed: {e}")

if __name__ == "__main__":
    main()
