"""
Simple Elasticsearch Client for SIEM Assistant MVP
Handles connection, querying, and data retrieval from Elasticsearch indices
"""

import os
import logging
import streamlit as st
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch
from elasticsearch.exceptions import ConnectionError, RequestError, NotFoundError
import random
import json
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SimpleElasticsearchClient:
    """Enhanced Elasticsearch client for SIEM Assistant with cloud support and mock fallback"""
    
    def __init__(self, host: str = None):
        """Initialize Elasticsearch client with automatic cloud/local/mock detection"""
        self.mock_mode = False
        self.client = None
        self.connected = False
        
        # Configure logging
        logger.info("Initializing SimpleElasticsearchClient")
        
        # Get host configuration
        es_host = self._get_elasticsearch_host(host)
        
        try:
            # Priority: Streamlit secrets > Environment variable > Parameter > Default
            self.client = Elasticsearch(
                [es_host],
                verify_certs=False,
                request_timeout=10,
                max_retries=2,
                retry_on_timeout=True
            )
            
            # Try to connect to Elasticsearch
            self.connected = self.client.ping()
            
            if self.connected:
                logger.info(f"✅ SUCCESS: Connected to Elasticsearch at {es_host}")
                try:
                    cluster_info = self.client.info()
                    logger.info(f"INFO: Cluster '{cluster_info['cluster_name']}', Version {cluster_info['version']['number']}")
                except Exception as e:
                    logger.warning(f"WARNING: Could not get cluster info: {e}")
            else:
                logger.warning("WARNING: Elasticsearch ping failed, switching to mock mode")
                self.mock_mode = True
                self.client = None
                
        except Exception as e:
            logger.warning(f"WARNING: Elasticsearch connection failed ({e}). Using mock mode.")
            self.mock_mode = True
            self.client = None

    def _get_elasticsearch_host(self, host_param: str = None) -> str:
        """Get Elasticsearch host from multiple sources with priority"""
        
        # Test connection
        try:
            # 1. Check Streamlit secrets for cloud deployment
            if hasattr(st, 'secrets') and 'ELASTICSEARCH_HOST' in st.secrets:
                es_host = st.secrets['ELASTICSEARCH_HOST']
                logger.info(f"Using Elasticsearch from Streamlit secrets: {es_host}")
                return es_host
        except Exception as e:
            logger.debug(f"No Streamlit secrets found: {e}")
        
        # 2. Check environment variable
        es_host = os.getenv('ELASTICSEARCH_HOST')
        if es_host:
            logger.info(f"Using Elasticsearch from environment: {es_host}")
            return es_host
        
        # 3. Use parameter
        if host_param:
            logger.info(f"Using Elasticsearch from parameter: {host_param}")
            return host_param
        
        # 4. Default to localhost
        default_host = "http://localhost:9200"
        logger.info(f"Using default Elasticsearch: {default_host}")
        return default_host

    def test_connection(self) -> bool:
        """Test if Elasticsearch is available"""
        if self.mock_mode:
            return True  # Mock mode is always "connected"
        
        try:
            return self.client.ping() if self.client else False
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    def get_available_indices(self) -> List[str]:
        """Get list of available indices for security analysis"""
        if self.mock_mode:
            return ["security-events-sample", "kibana_sample_data_logs"]
        
        try:
            if not self.connected:
                return []
            
            indices = self.client.cat.indices(format='json')
            security_patterns = ['security-events', 'kibana_sample_data_logs', 'winlogbeat', 'auditbeat', 'filebeat', 'packetbeat', 'siem-demo']
            
            available = []
            for index in indices:
                index_name = index['index']
                if any(pattern in index_name for pattern in security_patterns):
                    available.append(index_name)
            
            return available
        except Exception as e:
            logger.error(f"ERROR: Failed to get indices: {e}")
            return []

    def execute_security_query(self, query_text: str, index: str = None) -> Dict[str, Any]:
        """Execute security query against available indices"""
        if self.mock_mode:
            return self.mock_security_query(query_text)
        
        try:
            if not self.connected:
                return {"success": False, "error": "Not connected to Elasticsearch", "results": []}
            
            # Determine target index
            if not index:
                available_indices = self.get_available_indices()
                if any('security-events-sample' in idx.replace('-', '_') for idx in available_indices):
                    index = 'security-events-sample'
                elif 'kibana_sample_data_logs' in available_indices:
                    index = 'kibana_sample_data_logs'
                else:
                    all_indices = [idx['index'] for idx in self.client.cat.indices(format='json')]
                    security_indices = [idx for idx in all_indices if any(pattern in idx for pattern in ['security', 'log', 'event'])]
                    if security_indices:
                        index = security_indices[0]
                    else:
                        return {"success": False, "error": "No suitable security indices found", "results": []}
            
            # Convert query text to Elasticsearch DSL
            es_query = self.text_to_query(query_text, index)
            
            # Execute search
            result = self.client.search(index=index, body=es_query, size=20)
            
            return {
                "success": True,
                "total_hits": result['hits']['total']['value'],
                "results": [hit['_source'] for hit in result['hits']['hits']],
                "took": result.get('took', 0),
                "index_used": index,
                "query_type": self.get_query_type(query_text)
            }
            
        except NotFoundError:
            return {"success": False, "error": f"Index {index} not found. Available indices: {self.get_available_indices()}", "results": []}
        except Exception as e:
            return {"success": False, "error": str(e), "results": []}

    def execute_dsl_query(self, index: str, dsl_query: dict) -> Dict[str, Any]:
        """Execute pre-built Elasticsearch DSL query - NEW METHOD"""
        if self.mock_mode:
            # Generate mock response based on DSL query structure
            return self._mock_dsl_query_response(dsl_query)
        
        try:
            if not self.connected:
                return {"success": False, "error": "Not connected", "results": []}
            
            result = self.client.search(index=index, body=dsl_query)
            
            return {
                "success": True,
                "total_hits": result['hits']['total']['value'],
                "results": [hit['_source'] for hit in result['hits']['hits']],
                "took": result.get('took', 0),
                "raw_response": result  # For report generation
            }
        except Exception as e:
            logger.error(f"Error executing DSL query: {str(e)}")
            return {"success": False, "error": str(e), "results": []}

    def validate_index_fields(self, index: str, required_fields: List[str]) -> bool:
        """Check if index has required fields - NEW METHOD"""
        if self.mock_mode:
            return True  # Mock mode supports all fields
        
        try:
            if not self.connected:
                return False
                
            mapping = self.client.indices.get_mapping(index=index)
            
            if index not in mapping:
                return False
                
            index_fields = mapping[index]['mappings'].get('properties', {}).keys()
            return all(field in index_fields for field in required_fields)
            
        except Exception as e:
            logger.error(f"Error validating index fields: {str(e)}")
            return False

    def _mock_dsl_query_response(self, dsl_query: dict) -> Dict[str, Any]:
        """Generate mock response for DSL queries - NEW METHOD"""
        # Extract query size
        size = dsl_query.get('size', 10)
        
        # Generate mock events
        mock_events = []
        for i in range(min(size, 50)):  # Cap at 50 for performance
            event = {
                '@timestamp': (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
                'event': {
                    'type': random.choice(['malware', 'authentication', 'network', 'web']),
                    'category': random.choice(['malware', 'authentication', 'network', 'web']),
                    'severity': random.randint(3, 10),
                    'outcome': random.choice(['success', 'failure', 'blocked'])
                },
                'source': {'ip': f'192.168.{random.randint(1, 10)}.{random.randint(100, 250)}'},
                'destination': {'ip': f'10.0.{random.randint(1, 10)}.{random.randint(10, 100)}'},
                'user': {'name': f'user{random.randint(1, 50)}'},
                'rule': {
                    'id': f'{random.randint(1000, 9999)}',
                    'description': f'Mock security event #{i+1}',
                    'level': random.randint(3, 15)
                },
                'host': {'name': f'host-{random.randint(1, 20)}'},
                'network': {'protocol': random.choice(['tcp', 'udp', 'http', 'https'])}
            }
            mock_events.append(event)
        
        return {
            "success": True,
            "total_hits": len(mock_events),
            "results": mock_events,
            "took": random.randint(10, 100),
            "raw_response": {
                "hits": {"total": {"value": len(mock_events)}},
                "took": random.randint(10, 100)
            }
        }

    def text_to_query(self, query_text: str, index: str) -> Dict[str, Any]:
        """Convert natural language to Elasticsearch query with index-specific optimizations"""
        query_lower = query_text.lower()
        
        if 'kibana_sample_data_logs' in index:
            return self._build_kibana_logs_query(query_lower)
        else:
            return self._build_security_events_query(query_lower)

    def _build_security_events_query(self, query_lower: str) -> Dict[str, Any]:
        """Build query for security-events-sample index"""
        if 'failed login' in query_lower or 'login fail' in query_lower:
            return {"query": {"match": {"action": "login_failed"}}, "sort": [{"@timestamp": {"order": "desc"}}]}
        elif 'critical' in query_lower and 'severity' in query_lower:
            return {"query": {"match": {"severity": "critical"}}, "sort": [{"@timestamp": {"order": "desc"}}]}
        elif 'high' in query_lower and 'severity' in query_lower:
            return {"query": {"match": {"severity": "high"}}, "sort": [{"@timestamp": {"order": "desc"}}]}
        elif 'authentication' in query_lower or 'auth' in query_lower:
            return {"query": {"match": {"event_type": "authentication"}}, "sort": [{"@timestamp": {"order": "desc"}}]}
        elif 'network' in query_lower or 'scan' in query_lower:
            return {"query": {"match": {"event_type": "network"}}, "sort": [{"@timestamp": {"order": "desc"}}]}
        else:
            return {"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "desc"}}]}

    def _build_kibana_logs_query(self, query_lower: str) -> Dict[str, Any]:
        """Build query for Kibana sample web logs"""
        if 'error' in query_lower or 'fail' in query_lower or '404' in query_lower:
            return {
                "query": {
                    "bool": {
                        "should": [
                            {"range": {"response": {"gte": 400}}},
                            {"match": {"message": "error"}},
                            {"match": {"message": "fail"}}
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        elif 'attack' in query_lower or 'suspicious' in query_lower or 'security' in query_lower:
            return {
                "query": {
                    "bool": {
                        "should": [
                            {"range": {"response": {"gte": 400}}},
                            {"wildcard": {"request": "*admin*"}},
                            {"wildcard": {"request": "*login*"}},
                            {"wildcard": {"request": "*sql*"}},
                            {"range": {"bytes": {"gte": 10000}}}
                        ]
                    }
                },
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
        elif 'traffic' in query_lower or 'unusual' in query_lower or 'top' in query_lower:
            return {
                "query": {"match_all": {}},
                "sort": [{"bytes": {"order": "desc"}}],
                "aggs": {
                    "top_ips": {"terms": {"field": "clientip.keyword", "size": 10}},
                    "top_requests": {"terms": {"field": "request.keyword", "size": 10}}
                }
            }
        else:
            return {"query": {"match_all": {}}, "sort": [{"@timestamp": {"order": "desc"}}]}

    def get_query_type(self, query_text: str) -> str:
        """Determine the type of security query"""
        query_lower = query_text.lower()
        
        if any(term in query_lower for term in ['failed', 'login', 'auth']):
            return 'authentication_analysis'
        elif any(term in query_lower for term in ['critical', 'high', 'severity']):
            return 'severity_analysis'
        elif any(term in query_lower for term in ['network', 'scan', 'traffic']):
            return 'network_analysis'
        elif any(term in query_lower for term in ['error', 'fail', '404']):
            return 'error_analysis'
        elif any(term in query_lower for term in ['threat', 'intelligence', 'attack']):
            return 'threat_intelligence'
        else:
            return 'general_search'

    def get_threat_intelligence_summary(self, index: str = None) -> Dict[str, Any]:
        """Get comprehensive threat intelligence summary"""
        if self.mock_mode:
            return self.mock_threat_intelligence()
        
        try:
            if not self.connected:
                return {"success": False, "error": "Not connected"}
            
            if not index:
                available = self.get_available_indices()
                index = available[0] if available else 'security-events-sample'
            
            if 'kibana_sample_data_logs' in index:
                threat_query = {
                    "size": 0,
                    "aggs": {
                        "response_codes": {"terms": {"field": "response", "size": 10}},
                        "top_ips": {"terms": {"field": "clientip.keyword", "size": 10}},
                        "request_patterns": {"terms": {"field": "request.keyword", "size": 10}},
                        "hourly_activity": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1h"}},
                        "suspicious_activity": {
                            "filter": {"range": {"response": {"gte": 400}}},
                            "aggs": {"by_ip": {"terms": {"field": "clientip.keyword", "size": 5}}}
                        }
                    }
                }
            else:
                threat_query = {
                    "size": 0,
                    "aggs": {
                        "threat_landscape": {"terms": {"field": "event_type.keyword", "size": 10}},
                        "severity_distribution": {"terms": {"field": "severity.keyword", "size": 10}},
                        "top_attackers": {"terms": {"field": "source_ip.keyword", "size": 10}},
                        "attack_timeline": {"date_histogram": {"field": "@timestamp", "calendar_interval": "1h"}},
                        "failed_authentications": {
                            "filter": {"match": {"action": "login_failed"}},
                            "aggs": {
                                "by_user": {"terms": {"field": "username.keyword", "size": 5}},
                                "by_ip": {"terms": {"field": "source_ip.keyword", "size": 5}}
                            }
                        }
                    }
                }
            
            result = self.client.search(index=index, body=threat_query)
            
            return {
                "success": True,
                "index_analyzed": index,
                "threat_intelligence": result['aggregations'],
                "total_events": result['hits']['total']['value']
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    def search_by_mitre_attack(self, technique: str) -> Dict[str, Any]:
        """Search for events related to MITRE ATT&CK techniques"""
        if self.mock_mode:
            return self.mock_mitre_attack(technique)
        
        try:
            mitre_mapping = {
                't1110': {'name': 'Brute Force', 'description': 'Password guessing attacks', 'query': {"match": {"action": "login_failed"}}, 'tactic': 'Credential Access'},
                't1078': {'name': 'Valid Accounts', 'description': 'Use of legitimate accounts', 'query': {"match": {"event_type": "authentication"}}, 'tactic': 'Defense Evasion'},
                't1046': {'name': 'Network Service Scanning', 'description': 'Network reconnaissance', 'query': {"match": {"action": "network_scan"}}, 'tactic': 'Discovery'},
                't1059': {'name': 'Command and Scripting Interpreter', 'description': 'Malicious script execution', 'query': {"match": {"event_type": "malware"}}, 'tactic': 'Execution'},
                't1190': {'name': 'Exploit Public-Facing Application', 'description': 'Web application attacks', 'query': {"range": {"response": {"gte": 400}}}, 'tactic': 'Initial Access'}
            }
            
            technique_lower = technique.lower()
            if technique_lower not in mitre_mapping:
                return {"success": False, "error": f"MITRE technique {technique} not supported. Available: {list(mitre_mapping.keys())}"}
            
            mapping = mitre_mapping[technique_lower]
            
            available_indices = self.get_available_indices()
            if technique_lower == 't1190' and 'kibana_sample_data_logs' in available_indices:
                index = 'kibana_sample_data_logs'
            else:
                index = 'security-events-sample' if any('security-events' in idx.replace('-', '_') for idx in available_indices) else (available_indices[0] if available_indices else 'security-events-sample')
            
            query = {
                "query": mapping['query'],
                "sort": [{"@timestamp" if 'security-events' in index else "@timestamp": {"order": "desc"}}]
            }
            
            result = self.client.search(index=index, body=query, size=20)
            
            return {
                "success": True,
                "mitre_technique": technique.upper(),
                "technique_name": mapping['name'],
                "description": mapping['description'],
                "tactic": mapping['tactic'],
                "total_hits": result['hits']['total']['value'],
                "results": [hit['_source'] for hit in result['hits']['hits']],
                "index_searched": index
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    def get_security_summary(self) -> Dict[str, Any]:
        """Get comprehensive security events summary across all indices"""
        if self.mock_mode:
            return self.mock_security_summary()
        
        try:
            if not self.connected:
                return {"success": False, "error": "Not connected"}
            
            available_indices = self.get_available_indices()
            if not available_indices:
                return {"success": False, "error": "No security indices available"}
            
            summaries = {}
            for index in available_indices:
                try:
                    doc_count = self.count_documents(index)
                    
                    recent_query = {
                        "query": {"range": {"@timestamp" if 'security-events' in index else "@timestamp": {"gte": "now-24h"}}},
                        "size": 0
                    }
                    recent_result = self.client.search(index=index, body=recent_query)
                    recent_count = recent_result['hits']['total']['value']
                    
                    summaries[index] = {
                        "total_documents": doc_count,
                        "recent_24h": recent_count,
                        "status": "active" if recent_count > 0 else "inactive"
                    }
                except Exception as e:
                    summaries[index] = {"error": str(e), "status": "error"}
            
            return {
                "success": True,
                "indices_summary": summaries,
                "total_indices": len(available_indices)
            }
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    def count_documents(self, index: str) -> int:
        """Count total documents in an index"""
        try:
            if not self.connected:
                return 0
            result = self.client.count(index=index)
            return result['count']
        except Exception as e:
            logger.error(f"Failed to count documents in {index}: {e}")
            return 0

    def get_index_info(self) -> Dict[str, Any]:
        """Get comprehensive information about available indices"""
        if self.mock_mode:
            return {
                "success": True,
                "indices": [
                    {"name": "security-events-sample", "docs_count": 15420, "store_size": "2.4mb", "health": "green", "status": "open"},
                    {"name": "kibana_sample_data_logs", "docs_count": 14074, "store_size": "11.5mb", "health": "green", "status": "open"}
                ]
            }
        
        try:
            if not self.connected:
                return {"success": False, "error": "Not connected"}
            
            indices = self.client.cat.indices(format='json')
            security_indices = []
            
            for index in indices:
                index_name = index['index']
                if any(pattern in index_name for pattern in ['security', 'log', 'event', 'beat', 'kibana_sample']):
                    security_indices.append({
                        "name": index_name,
                        "docs_count": int(index.get('docs.count', 0)),
                        "store_size": index.get('store.size', '0b'),
                        "health": index.get('health', 'unknown'),
                        "status": index.get('status', 'unknown')
                    })
            
            return {"success": True, "indices": security_indices}
            
        except Exception as e:
            return {"success": False, "error": str(e)}

    # MOCK DATA METHODS (Enhanced for better integration)
    def mock_security_query(self, query_text: str) -> Dict[str, Any]:
        """Generate mock security query results matching Kibana structure"""
        mock_events = []
        query_lower = query_text.lower()
        
        # Determine event type based on query
        if 'failed' in query_lower or 'login' in query_lower:
            event_types = {'authentication': 8, 'intrusion': 2}
        elif 'critical' in query_lower or 'high' in query_lower:
            event_types = {'malware': 5, 'intrusion': 3, 'authentication': 2}
        elif 'network' in query_lower:
            event_types = {'network': 7, 'intrusion': 3}
        else:
            event_types = {'authentication': 3, 'network': 3, 'malware': 3, 'intrusion': 3}
        
        for event_type, count in event_types.items():
            for i in range(count):
                mock_events.append({
                    '@timestamp': (datetime.now() - timedelta(hours=random.randint(1, 168))).isoformat(),
                    'event_type': event_type,
                    'severity': random.choice(['low', 'medium', 'high', 'critical']),
                    'source_ip': f'192.168.{random.randint(1,10)}.{random.randint(1,254)}',
                    'username': random.choice(['admin', 'user1', 'service_account', 'guest', 'root']),
                    'action': random.choice(['blocked', 'allowed', 'detected', 'denied', 'login_failed']),
                    'description': f'Mock security event detected from automated system'
                })
        
        return {
            "success": True,
            "index_used": "security-events-sample (DEMO MODE)",
            "query_type": self.get_query_type(query_text),
            "total_hits": len(mock_events),
            "results": mock_events,
            "took": random.randint(2, 12)
        }

    def mock_threat_intelligence(self) -> Dict[str, Any]:
        """Generate mock threat intelligence matching real structure"""
        return {
            "success": True,
            "index_analyzed": "security-events-sample (DEMO MODE)",
            "total_events": 15420,
            "threat_intelligence": {
                "threat_landscape": {
                    "buckets": [
                        {"key": "authentication", "doc_count": 4850},
                        {"key": "intrusion", "doc_count": 3920},
                        {"key": "malware", "doc_count": 3250},
                        {"key": "network", "doc_count": 2100},
                        {"key": "data_exfiltration", "doc_count": 1300}
                    ]
                },
                "severity_distribution": {
                    "buckets": [
                        {"key": "low", "doc_count": 5280},
                        {"key": "medium", "doc_count": 6150},
                        {"key": "high", "doc_count": 2840},
                        {"key": "critical", "doc_count": 1150}
                    ]
                },
                "failed_authentications": {
                    "doc_count": 1245,
                    "by_user": {
                        "buckets": [
                            {"key": "admin", "doc_count": 325},
                            {"key": "root", "doc_count": 287},
                            {"key": "user1", "doc_count": 198},
                            {"key": "service_account", "doc_count": 245},
                            {"key": "guest", "doc_count": 190}
                        ]
                    }
                }
            }
        }

    def mock_mitre_attack(self, technique: str) -> Dict[str, Any]:
        """Generate mock MITRE ATT&CK results"""
        technique_info = {
            't1110': {'name': 'Brute Force', 'tactic': 'Credential Access', 'desc': 'Password guessing attacks'},
            't1078': {'name': 'Valid Accounts', 'tactic': 'Defense Evasion', 'desc': 'Use of legitimate credentials'},
            't1046': {'name': 'Network Scanning', 'tactic': 'Discovery', 'desc': 'Network reconnaissance'},
            't1059': {'name': 'Command Execution', 'tactic': 'Execution', 'desc': 'Malicious script execution'},
            't1190': {'name': 'Exploit Web App', 'tactic': 'Initial Access', 'desc': 'Web application attacks'}
        }
        
        tech_key = technique.lower()
        tech = technique_info.get(tech_key, {'name': 'Unknown', 'tactic': 'Unknown', 'desc': 'No data'})
        
        mock_events = []
        for i in range(8):
            mock_events.append({
                '@timestamp': (datetime.now() - timedelta(hours=random.randint(1, 72))).isoformat(),
                'severity': random.choice(['medium', 'high', 'critical']),
                'source_ip': f'192.168.{random.randint(1,254)}.{random.randint(1,254)}',
                'action': random.choice(['blocked', 'detected', 'allowed']),
                'username': random.choice(['admin', 'user1', 'service_account']),
                'mitre_technique': technique.upper(),
                'description': f'{tech["name"]} attempt detected'
            })
        
        return {
            "success": True,
            "mitre_technique": technique.upper(),
            "technique_name": tech['name'],
            "description": tech['desc'],
            "tactic": tech['tactic'],
            "index_searched": "security-events-sample (DEMO MODE)",
            "total_hits": len(mock_events),
            "results": mock_events
        }

    def mock_security_summary(self) -> Dict[str, Any]:
        """Generate mock security summary"""
        return {
            "success": True,
            "total_indices": 2,
            "indices_summary": {
                "security-events-sample": {"status": "active", "total_documents": 15420, "recent_24h": 1285},
                "kibana_sample_data_logs": {"status": "active", "total_documents": 14074, "recent_24h": 1042}
            }
        }

    def get_connection_status(self) -> Dict[str, Any]:
        """Get detailed connection status information"""
        status = {
            "connected": self.connected,
            "mock_mode": self.mock_mode,
            "client_available": self.client is not None
        }
        
        if self.connected and self.client:
            try:
                cluster_info = self.client.info()
                status.update({
                    "cluster_name": cluster_info.get('cluster_name', 'Unknown'),
                    "version": cluster_info.get('version', {}).get('number', 'Unknown'),
                    "indices_count": len(self.get_available_indices())
                })
            except Exception as e:
                status["info_error"] = str(e)
        elif self.mock_mode:
            status.update({
                "cluster_name": "Mock Mode",
                "version": "Demo",
                "indices_count": 2
            })
        
        return status

    def __del__(self):
        """Cleanup on object destruction"""
        if self.client:
            try:
                self.client.transport.close()
            except:
                pass


# Example usage and testing
if __name__ == "__main__":
    # Initialize client
    client = SimpleElasticsearchClient()
    
    # Test connection
    status = client.get_connection_status()
    print(f"Connection Status: {status}")
    
    if status.get('connected') or status.get('mock_mode'):
        print("✅ Client ready")
        
        # Test basic operations
        indices = client.get_available_indices()
        print(f"Available indices: {indices}")
        
        # Test sample query
        result = client.execute_security_query("show me failed login attempts")
        print(f"Query result: {result.get('total_hits', 0)} hits")
        
        # Test DSL query
        dsl_query = {"query": {"match_all": {}}, "size": 5}
        dsl_result = client.execute_dsl_query("security-events-sample", dsl_query)
        print(f"DSL query result: {dsl_result.get('total_hits', 0)} hits")
        
    else:
        print("❌ Connection failed")
        print("Make sure Elasticsearch is running and accessible")
