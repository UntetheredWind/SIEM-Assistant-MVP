import re
import json
import logging
from typing import Dict, List, Optional, Any, Union, Tuple
from datetime import datetime, timedelta
from elasticsearch.exceptions import RequestError

logger = logging.getLogger(__name__)

class KQLTranslator:
    """Translates KQL queries to Elasticsearch DSL"""
    
    def __init__(self):
        """Initialize KQL translator with field mappings"""
        self.operators = {
            'and': 'must',
            'or': 'should', 
            'not': 'must_not'
        }
        
        self.comparison_operators = {
            ':': 'match',
            '=': 'term',
            '!=': 'must_not_term',
            '>': 'range_gt',
            '<': 'range_lt',
            '>=': 'range_gte',
            '<=': 'range_lte'
        }
    
    def parse_kql_query(self, kql_query: str) -> Dict[str, Any]:
        """Parse KQL query and convert to Elasticsearch DSL"""
        try:
            # Clean and normalize the query
            kql_query = kql_query.strip()
            
            if not kql_query:
                return {"match_all": {}}
            
            # Handle special cases
            if kql_query.lower() == "*":
                return {"match_all": {}}
            
            # Parse the query into components
            parsed_query = self._parse_query_components(kql_query)
            
            # Convert to Elasticsearch DSL
            es_query = self._convert_to_es_dsl(parsed_query)
            
            return es_query
            
        except Exception as e:
            logger.error(f"Failed to parse KQL query '{kql_query}': {str(e)}")
            # Fallback to query_string query
            return {
                "query_string": {
                    "query": kql_query,
                    "default_operator": "AND"
                }
            }
    
    def _parse_query_components(self, query: str) -> Dict[str, Any]:
        """Parse KQL query into structured components"""
        # This is a simplified parser - a full implementation would use a proper parser
        
        # Handle parentheses
        query = query.replace('(', ' ( ').replace(')', ' ) ')
        
        # Split by logical operators while preserving them
        tokens = []
        current_token = ""
        
        i = 0
        while i < len(query):
            char = query[i]
            
            if char == '"':
                # Handle quoted strings
                current_token += char
                i += 1
                while i < len(query) and query[i] != '"':
                    current_token += query[i]
                    i += 1
                if i < len(query):
                    current_token += query[i]  # closing quote
            elif char in ' \t\n':
                if current_token.strip():
                    tokens.append(current_token.strip())
                    current_token = ""
            else:
                current_token += char
            
            i += 1
        
        if current_token.strip():
            tokens.append(current_token.strip())
        
        return {"tokens": tokens}
    
    def _convert_to_es_dsl(self, parsed_query: Dict[str, Any]) -> Dict[str, Any]:
        """Convert parsed query to Elasticsearch DSL"""
        tokens = parsed_query.get("tokens", [])
        
        if not tokens:
            return {"match_all": {}}
        
        # Simple conversion for demonstration
        # A full implementation would handle complex boolean logic
        
        bool_query = {
            "bool": {
                "must": [],
                "should": [],
                "must_not": []
            }
        }
        
        current_operator = "must"
        i = 0
        
        while i < len(tokens):
            token = tokens[i].lower()
            
            if token in ["and", "or", "not"]:
                if token == "and":
                    current_operator = "must"
                elif token == "or":
                    current_operator = "should"
                elif token == "not":
                    current_operator = "must_not"
                i += 1
                continue
            
            # Handle field:value pairs
            if ":" in token and not token.startswith("http"):
                field, value = token.split(":", 1)
                field = field.strip()
                value = value.strip().strip('"')
                
                if value == "*":
                    query_clause = {"exists": {"field": field}}
                elif "*" in value or "?" in value:
                    query_clause = {"wildcard": {field: value}}
                else:
                    query_clause = {"match": {field: value}}
                
                bool_query["bool"][current_operator].append(query_clause)
            else:
                # Free text search
                query_clause = {"query_string": {"query": token}}
                bool_query["bool"][current_operator].append(query_clause)
            
            i += 1
        
        # Clean up empty clauses
        for clause_type in ["must", "should", "must_not"]:
            if not bool_query["bool"][clause_type]:
                del bool_query["bool"][clause_type]
        
        # If only one clause type, simplify
        if len(bool_query["bool"]) == 1:
            clause_type, clauses = next(iter(bool_query["bool"].items()))
            if len(clauses) == 1:
                return clauses[0]
        
        return bool_query

class QueryExecutor:
    """Execute and validate queries against Elasticsearch"""
    
    def __init__(self, elasticsearch_client):
        """Initialize query executor"""
        self.es_client = elasticsearch_client
        self.kql_translator = KQLTranslator()
        
        # Query validation rules
        self.validation_rules = {
            'max_size': 10000,
            'default_size': 100,
            'timeout': '30s',
            'max_aggregation_size': 1000
        }
    
    def execute_kql_query(self, 
                         kql_query: str,
                         index: str,
                         time_range: Optional[Dict[str, str]] = None,
                         size: int = 100,
                         sort_field: str = "@timestamp",
                         sort_order: str = "desc") -> Dict[str, Any]:
        """Execute KQL query against Elasticsearch"""
        try:
            # Translate KQL to Elasticsearch DSL
            es_query = self.kql_translator.parse_kql_query(kql_query)
            
            # Add time range filter if provided
            if time_range:
                range_filter = self._build_time_range_filter(time_range)
                if range_filter:
                    if "bool" not in es_query:
                        es_query = {"bool": {"must": [es_query]}}
                    elif "must" not in es_query["bool"]:
                        es_query["bool"]["must"] = []
                    
                    es_query["bool"]["must"].append(range_filter)
            
            # Validate and execute query
            return self.execute_es_query(es_query, index, size, sort_field, sort_order)
            
        except Exception as e:
            logger.error(f"Failed to execute KQL query: {str(e)}")
            return {
                'error': str(e),
                'query_type': 'KQL',
                'original_query': kql_query,
                'timestamp': datetime.now().isoformat()
            }
    
    def execute_es_query(self,
                        es_query: Dict[str, Any],
                        index: str,
                        size: int = 100,
                        sort_field: str = "@timestamp", 
                        sort_order: str = "desc") -> Dict[str, Any]:
        """Execute Elasticsearch DSL query"""
        try:
            # Validate query parameters
            validated_params = self._validate_query_params(size, sort_field, sort_order)
            
            # Build sort configuration
            sort_config = [{validated_params['sort_field']: {'order': validated_params['sort_order']}}]
            
            # Execute query
            response = self.es_client.execute_query(
                index=index,
                query=es_query,
                size=validated_params['size'],
                sort=sort_config,
                timeout=self.validation_rules['timeout']
            )
            
            # Process and enrich response
            processed_response = self._process_query_response(response, es_query, index)
            
            return processed_response
            
        except RequestError as e:
            logger.error(f"Elasticsearch query error: {str(e)}")
            return {
                'error': f"Query execution failed: {str(e)}",
                'query_type': 'Elasticsearch DSL',
                'elasticsearch_query': es_query,
                'timestamp': datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Unexpected error executing query: {str(e)}")
            return {
                'error': str(e),
                'query_type': 'Elasticsearch DSL',
                'elasticsearch_query': es_query,
                'timestamp': datetime.now().isoformat()
            }
    
    def _build_time_range_filter(self, time_range: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Build time range filter for queries"""
        try:
            range_filter = {
                "range": {
                    "@timestamp": {}
                }
            }
            
            if "gte" in time_range:
                range_filter["range"]["@timestamp"]["gte"] = time_range["gte"]
            elif "from" in time_range:
                range_filter["range"]["@timestamp"]["gte"] = time_range["from"]
            
            if "lte" in time_range:
                range_filter["range"]["@timestamp"]["lte"] = time_range["lte"]
            elif "to" in time_range:
                range_filter["range"]["@timestamp"]["lte"] = time_range["to"]
            
            # Handle relative time ranges
            if "last" in time_range:
                last_value = time_range["last"]
                if "h" in last_value:
                    hours = int(last_value.replace("h", ""))
                    range_filter["range"]["@timestamp"]["gte"] = f"now-{hours}h"
                elif "d" in last_value:
                    days = int(last_value.replace("d", ""))
                    range_filter["range"]["@timestamp"]["gte"] = f"now-{days}d"
                elif "m" in last_value:
                    minutes = int(last_value.replace("m", ""))
                    range_filter["range"]["@timestamp"]["gte"] = f"now-{minutes}m"
            
            return range_filter if range_filter["range"]["@timestamp"] else None
            
        except Exception as e:
            logger.warning(f"Failed to build time range filter: {str(e)}")
            return None
    
    def _validate_query_params(self, size: int, sort_field: str, sort_order: str) -> Dict[str, Any]:
        """Validate and sanitize query parameters"""
        # Validate size
        validated_size = min(max(1, size), self.validation_rules['max_size'])
        if validated_size != size:
            logger.warning(f"Query size adjusted from {size} to {validated_size}")
        
        # Validate sort field (basic sanitization)
        validated_sort_field = re.sub(r'[^a-zA-Z0-9._@-]', '', sort_field) or "@timestamp"
        
        # Validate sort order
        validated_sort_order = sort_order.lower() if sort_order.lower() in ['asc', 'desc'] else 'desc'
        
        return {
            'size': validated_size,
            'sort_field': validated_sort_field,
            'sort_order': validated_sort_order
        }
    
    def _process_query_response(self, 
                              response: Dict[str, Any], 
                              original_query: Dict[str, Any],
                              index: str) -> Dict[str, Any]:
        """Process and enrich query response"""
        try:
            processed_response = {
                'query_info': {
                    'index': index,
                    'elasticsearch_query': original_query,
                    'execution_time_ms': response.get('execution_time_ms', 0),
                    'took': response.get('took', 0),
                    'timed_out': response.get('timed_out', False)
                },
                'results': {
                    'total_hits': response.get('total_hits', 0),
                    'returned_hits': len(response.get('hits', {}).get('hits', [])),
                    'max_score': response.get('hits', {}).get('max_score'),
                    'hits': []
                },
                'aggregations': response.get('aggregations', {}),
                'timestamp': datetime.now().isoformat()
            }
            
            # Process individual hits
            for hit in response.get('hits', {}).get('hits', []):
                processed_hit = {
                    'id': hit.get('_id'),
                    'index': hit.get('_index'),
                    'score': hit.get('_score'),
                    'source': hit.get('_source', {}),
                    'highlight': hit.get('highlight', {})
                }
                processed_response['results']['hits'].append(processed_hit)
            
            return processed_response
            
        except Exception as e:
            logger.error(f"Failed to process query response: {str(e)}")
            return {
                'error': f"Response processing failed: {str(e)}",
                'raw_response': response,
                'timestamp': datetime.now().isoformat()
            }
    
    def get_query_explanation(self, 
                            query: Union[str, Dict[str, Any]], 
                            index: str,
                            query_type: str = "KQL") -> Dict[str, Any]:
        """Get detailed explanation of query execution"""
        try:
            # Convert KQL to ES DSL if needed
            if query_type.upper() == "KQL" and isinstance(query, str):
                es_query = self.kql_translator.parse_kql_query(query)
                original_query = query
            else:
                es_query = query if isinstance(query, dict) else {"match_all": {}}
                original_query = query
            
            # Use Elasticsearch explain API
            explain_response = self.es_client.client.indices.validate_query(
                index=index,
                body={"query": es_query},
                explain=True
            )
            
            return {
                'original_query': original_query,
                'query_type': query_type,
                'elasticsearch_query': es_query,
                'valid': explain_response.get('valid', False),
                'explanations': explain_response.get('explanations', []),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to explain query: {str(e)}")
            return {
                'error': str(e),
                'original_query': query,
                'query_type': query_type,
                'timestamp': datetime.now().isoformat()
            }
    
    def get_security_queries(self) -> Dict[str, Dict[str, Any]]:
        """Get predefined security queries for common use cases"""
        return {
            'failed_logins': {
                'name': 'Failed Login Attempts',
                'description': 'Detect multiple failed authentication attempts',
                'kql': 'event.category: authentication AND event.outcome: failure',
                'es_dsl': {
                    "bool": {
                        "must": [
                            {"match": {"event.category": "authentication"}},
                            {"match": {"event.outcome": "failure"}}
                        ]
                    }
                },
                'time_range': {'last': '1h'},
                'aggregations': {
                    'source_ips': {
                        'terms': {'field': 'source.ip'}
                    }
                }
            },
            'suspicious_processes': {
                'name': 'Suspicious Process Execution',
                'description': 'Detect suspicious process execution patterns',
                'kql': 'event.category: process AND process.name: (powershell.exe OR cmd.exe OR wscript.exe)',
                'es_dsl': {
                    "bool": {
                        "must": [
                            {"match": {"event.category": "process"}},
                            {"terms": {"process.name": ["powershell.exe", "cmd.exe", "wscript.exe"]}}
                        ]
                    }
                },
                'time_range': {'last': '24h'}
            },
            'network_anomalies': {
                'name': 'Network Traffic Anomalies',
                'description': 'Detect unusual network connections',
                'kql': 'destination.port: (445 OR 3389 OR 22) AND source.ip: 192.168.*',
                'es_dsl': {
                    "bool": {
                        "must": [
                            {"terms": {"destination.port": [445, 3389, 22]}},
                            {"wildcard": {"source.ip": "192.168.*"}}
                        ]
                    }
                },
                'time_range': {'last': '4h'}
            }
        }
