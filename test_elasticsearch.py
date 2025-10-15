from Integrations.elasticsearch_client import SimpleElasticsearchClient
import json

def test_elasticsearch_integration():
    print("=== Testing Elasticsearch Integration ===")
    
    # Initialize client
    client = SimpleElasticsearchClient()
    
    # Test connection
    if client.test_connection():
        print("Connection successful")
    else:
        print("Connection failed")
        return
    
    # Test queries
    test_queries = [
        "Show me failed login attempts",
        "Find critical severity events", 
        "List authentication events",
        "Get recent security events"
    ]
    
    for query in test_queries:
        print(f"\n--- Testing: '{query}' ---")
        result = client.execute_security_query(query)
        
        if result["success"]:
            print(f"Found {result['total_hits']} results")
            if result["results"]:
                print(f"Sample result: {json.dumps(result['results'][0], indent=2)}")
        else:
            print(f"Error: {result['error']}")

if __name__ == "__main__":
    test_elasticsearch_integration()
