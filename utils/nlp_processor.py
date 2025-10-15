import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class QueryIntent:
    """Data class for parsed query intent"""
    def __init__(self, intent_type: str, entities: Dict, confidence: float, es_query: Optional[Dict] = None):
        self.intent_type = intent_type
        self.entities = entities
        self.confidence = confidence
        self.es_query = es_query


class SecurityNLPProcessor:
    """All-in-one NLP processor for SIEM queries"""
    
    def __init__(self):
        logger.info("Initializing SecurityNLPProcessor")
        
        self.security_patterns = {
            'threat_types': [
                'malware', 'virus', 'trojan', 'ransomware', 'rootkit', 'worm', 'spyware',
                'phishing', 'spear phishing', 'social engineering', 'whaling',
                'brute force', 'bruteforce', 'password attack', 'credential stuffing',
                'ddos', 'dos attack', 'denial of service', 'amplification attack',
                'sql injection', 'sqli', 'xss', 'cross site scripting', 'csrf',
                'privilege escalation', 'lateral movement', 'persistence',
                'data exfiltration', 'insider threat', 'data breach',
                'apt', 'advanced persistent threat', 'backdoor', 'c2', 'command and control',
                'botnet', 'cryptocurrency mining', 'cryptojacking', 'firewall'
            ],
            'severity_levels': ['critical', 'high', 'medium', 'low', 'info', 'informational'],
            'mitre_techniques': [
                't1110', 't1078', 't1190', 't1046', 't1059', 't1055', 't1003', 't1021',
                't1083', 't1135', 't1018', 't1057', 't1087', 't1012', 't1047', 't1005',
                't1115', 't1071', 't1027', 't1036', 't1090', 't1053', 't1204', 't1566'
            ],
            'time_patterns': {
                'yesterday': lambda: (datetime.now() - timedelta(days=1), datetime.now() - timedelta(days=1, seconds=-86400)),
                'today': lambda: (datetime.now().replace(hour=0, minute=0, second=0), datetime.now()),
                'last week': lambda: (datetime.now() - timedelta(days=7), datetime.now()),
                'past week': lambda: (datetime.now() - timedelta(days=7), datetime.now()),
                'last month': lambda: (datetime.now() - timedelta(days=30), datetime.now()),
                'last hour': lambda: (datetime.now() - timedelta(hours=1), datetime.now()),
                'last 24 hours': lambda: (datetime.now() - timedelta(hours=24), datetime.now()),
                'last 2 hours': lambda: (datetime.now() - timedelta(hours=2), datetime.now()),
                'last 6 hours': lambda: (datetime.now() - timedelta(hours=6), datetime.now()),
                'last 12 hours': lambda: (datetime.now() - timedelta(hours=12), datetime.now()),
                'this week': lambda: (datetime.now() - timedelta(days=7), datetime.now()),
                'this month': lambda: (datetime.now() - timedelta(days=30), datetime.now())
            },
            'protocols': ['http', 'https', 'ssh', 'ftp', 'smtp', 'dns', 'tcp', 'udp', 'icmp', 'rdp', 'smb'],
            'attack_vectors': ['web', 'email', 'network', 'endpoint', 'mobile', 'cloud', 'iot'],
            'event_outcomes': ['success', 'failure', 'blocked', 'allowed', 'dropped', 'accepted', 'denied']
        }
        
        self.schema_mappings = {
            'security_events': {
                'timestamp': '@timestamp',
                'source_ip': 'source.ip',
                'dest_ip': 'destination.ip',
                'user': 'user.name',
                'event_type': 'event.type',
                'event_category': 'event.category',
                'event_outcome': 'event.outcome',
                'severity': 'event.severity',
                'protocol': 'network.protocol',
                'port': 'destination.port',
                'process': 'process.name',
                'rule_id': 'rule.id',
                'rule_name': 'rule.name',
                'rule_description': 'rule.description',
                'rule_level': 'rule.level',
                'host_name': 'host.name',
                'file_name': 'file.name',
                'file_hash': 'file.hash'
            },
            'kibana_sample_data_logs': {
                'timestamp': '@timestamp',
                'source_ip': 'clientip',
                'response_code': 'response',
                'bytes': 'bytes',
                'request': 'request',
                'agent': 'agent',
                'machine_os': 'machine.os',
                'machine_ram': 'machine.ram',
                'geo_country': 'geoip.country_name'
            }
        }
        
        self.intent_patterns = {
            'search': [
                r'\b(?:show|find|search|list|get|display|retrieve)\b',
                r'\b(?:what are|which are|where are)\b',
                r'\b(?:give me|tell me)\b.*\b(?:events|alerts|logs|data)\b'
            ],
            'aggregate': [
                r'\b(?:count|sum|average|avg|max|min|total)\b',
                r'\btop\s+\d+\b',
                r'\b(?:group by|breakdown|distribution|statistics|stats)\b',
                r'\b(?:how many|number of)\b'
            ],
            'report': [
                r'\b(?:generate|create|produce|build)\b.*\b(?:report|summary|analysis)\b',
                r'\b(?:security\s+report|threat\s+report|incident\s+report)\b',
                r'\b(?:executive\s+summary|dashboard|overview)\b',
                r'\breport\s+for\b'
            ],
            'threat_analysis': [
                r'\b(?:analyze|investigate|examine)\b.*\b(?:threat|attack|malicious|suspicious)\b',
                r'\b(?:threat\s+hunting|incident\s+response|forensic)\b',
                r'\b(?:anomaly|unusual|abnormal)\b.*\b(?:activity|behavior|pattern)\b'
            ],
            'mitre_attack': [
                r'\bt\d{4}\b',
                r'\b(?:mitre|att&ck|attack)\b.*\b(?:technique|tactic|framework)\b',
                r'\b(?:kill\s+chain|attack\s+pattern|ttp)\b'
            ]
        }
        
        # Enhanced format detection patterns
        self.format_patterns = {
            'chart_request': [
                r'\b(?:chart|graph|plot|visualiz|visual)\b',
                r'\b(?:pie|bar|line|histogram|scatter)\b.*\b(?:chart|graph)\b',
                r'\bwith\s+(?:charts?|graphs?|visualization)\b'
            ],
            'table_request': [
                r'\b(?:table|list|breakdown)\b',
                r'\bin\s+(?:table|tabular)\s+format\b',
                r'\bas\s+(?:csv|spreadsheet|table)\b'
            ],
            'report_request': [
                r'\b(?:report|summary|analysis)\b',
                r'\bcomprehensive\b.*\b(?:analysis|report)\b',
                r'\bdetailed\b.*\b(?:summary|breakdown)\b'
            ]
        }
    
    def process_query(self, query: str) -> QueryIntent:
        """Main entry point - classifies intent and generates ES query"""
        try:
            # Clean and normalize query
            cleaned_query = query.lower().strip()
            logger.info(f"🔍 NLP Processing: '{cleaned_query[:50]}...'")
            
            # Classify intent
            intent_type = self._classify_intent(cleaned_query)
            logger.info(f"📊 Classified intent: {intent_type}")
            
            # Extract entities
            entities = self._extract_entities(cleaned_query)
            logger.info(f"🎯 Extracted entities: threats={len(entities.get('threats', []))}, time_range={'yes' if entities.get('time_range') else 'no'}")
            
            # Calculate confidence based on pattern matches
            confidence = self._calculate_confidence(cleaned_query, intent_type, entities)
            logger.info(f"✅ Confidence score: {confidence:.2f}")
            
            # Generate Elasticsearch query if applicable
            es_query = None
            should_use_gemini = self.should_use_gemini(query)
            logger.info(f"🤖 Should use Gemini: {should_use_gemini}")
            
            if not should_use_gemini:
                intent_obj = QueryIntent(intent_type, entities, confidence)
                es_query = self._generate_elasticsearch_query(intent_obj)
                logger.info(f"🔍 Generated ES query: {'Yes (' + str(len(str(es_query))) + ' chars)' if es_query else 'No'}")
            
            return QueryIntent(intent_type, entities, confidence, es_query)
            
        except Exception as e:
            logger.error(f"❌ Error processing query: {e}")
            return QueryIntent('unknown', {}, 0.0)
    
    def _classify_intent(self, query: str) -> str:
        """Detect query intent using pattern matching"""
        intent_scores = {}
        
        for intent, patterns in self.intent_patterns.items():
            score = 0
            for pattern in patterns:
                matches = len(re.findall(pattern, query, re.IGNORECASE))
                score += matches
                if matches > 0:
                    logger.debug(f"Intent '{intent}' matched pattern: {pattern}")
            intent_scores[intent] = score
        
        # Special handling for specific keywords
        if any(word in query for word in ['malware', 'virus', 'threat', 'attack', 'suspicious']):
            intent_scores['threat_analysis'] = intent_scores.get('threat_analysis', 0) + 2
            logger.debug("Boosted threat_analysis for security keywords")
        
        if any(word in query for word in ['report', 'summary', 'analysis', 'overview']):
            intent_scores['report'] = intent_scores.get('report', 0) + 3
            logger.debug("Boosted report intent for report keywords")
        
        if re.search(r'\btop\s+\d+\b', query):
            intent_scores['aggregate'] = intent_scores.get('aggregate', 0) + 3
        
        # Return intent with highest score, default to 'search'
        if max(intent_scores.values()) == 0:
            logger.debug("No patterns matched, defaulting to search")
            return 'search'
        
        best_intent = max(intent_scores.items(), key=lambda x: x[1])[0]
        logger.debug(f"Intent scores: {intent_scores}, selected: {best_intent}")
        return best_intent
    
    def _extract_entities(self, query: str) -> Dict:
        """Extract security entities (IPs, users, threats, time)"""
        entities = {
            'index': 'security-events-sample',  # Default index
            'time_range': None,
            'ips': [],
            'users': [],
            'threats': [],
            'severity': None,
            'mitre_techniques': [],
            'protocols': [],
            'event_outcomes': [],
            'limit': 15,  # Increased default for better demos
            'format_preferences': []
        }
        
        # Extract IP addresses (IPv4)
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        entities['ips'] = re.findall(ip_pattern, query)
        if entities['ips']:
            logger.debug(f"Extracted IPs: {entities['ips']}")
        
        # Extract time ranges - DEFAULT to last 24 hours for reports/data queries
        time_extracted = False
        for time_key, time_func in self.security_patterns['time_patterns'].items():
            if time_key in query:
                start_time, end_time = time_func()
                entities['time_range'] = {
                    'gte': start_time.isoformat(),
                    'lte': end_time.isoformat(),
                    'format': time_key
                }
                logger.debug(f"Extracted time range: {time_key}")
                time_extracted = True
                break
        
        # If no time range specified but it's a data query, default to last 24 hours
        if not time_extracted and any(word in query for word in ['report', 'events', 'logs', 'show', 'find', 'malware']):
            start_time = datetime.now() - timedelta(hours=24)
            end_time = datetime.now()
            entities['time_range'] = {
                'gte': start_time.isoformat(),
                'lte': end_time.isoformat(),
                'format': 'last_24_hours_default'
            }
            logger.debug("Applied default 24-hour time range")
        
        # Extract threat types
        for threat in self.security_patterns['threat_types']:
            if threat in query:
                entities['threats'].append(threat)
        
        if entities['threats']:
            logger.debug(f"Extracted threats: {entities['threats']}")
        
        # Extract severity levels
        for severity in self.security_patterns['severity_levels']:
            if severity in query:
                entities['severity'] = severity
                logger.debug(f"Extracted severity: {severity}")
                break
        
        # Extract MITRE techniques
        mitre_pattern = r'\bt(\d{4})\b'
        mitre_matches = re.findall(mitre_pattern, query, re.IGNORECASE)
        for match in mitre_matches:
            technique = f'T{match}'
            entities['mitre_techniques'].append(technique)
        
        # Also check for full technique names
        for technique in self.security_patterns['mitre_techniques']:
            if technique.lower() in query:
                entities['mitre_techniques'].append(technique.upper())
        
        if entities['mitre_techniques']:
            logger.debug(f"Extracted MITRE techniques: {entities['mitre_techniques']}")
        
        # Extract protocols and outcomes
        for protocol in self.security_patterns['protocols']:
            if protocol in query:
                entities['protocols'].append(protocol)
        
        for outcome in self.security_patterns['event_outcomes']:
            if outcome in query:
                entities['event_outcomes'].append(outcome)
        
        # Extract usernames
        user_patterns = [
            r'user[:\s]+(\w+)', r'username[:\s]+(\w+)', r'account[:\s]+(\w+)',
            r'from\s+user\s+(\w+)', r'by\s+(\w+)(?:\s+user)?'
        ]
        for pattern in user_patterns:
            matches = re.findall(pattern, query, re.IGNORECASE)
            entities['users'].extend(matches)
        
        # Extract numbers for top N queries
        top_match = re.search(r'top\s+(\d+)', query, re.IGNORECASE)
        if top_match:
            entities['limit'] = min(int(top_match.group(1)), 100)
        
        # Extract format preferences
        for format_type, patterns in self.format_patterns.items():
            for pattern in patterns:
                if re.search(pattern, query, re.IGNORECASE):
                    entities['format_preferences'].append(format_type)
                    break
        
        # Detect index preferences
        if any(keyword in query for keyword in ['kibana', 'sample', 'web', 'http']):
            entities['index'] = 'kibana_sample_data_logs'
        elif any(keyword in query for keyword in ['security', 'events', 'alerts', 'malware', 'firewall']):
            entities['index'] = 'security-events-sample'
        
        return entities
    
    def _calculate_confidence(self, query: str, intent_type: str, entities: Dict) -> float:
        """Calculate confidence score based on pattern matches and entity extraction"""
        confidence = 0.5  # Base confidence
        
        # Boost confidence for intent pattern matches
        intent_patterns = self.intent_patterns.get(intent_type, [])
        for pattern in intent_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                confidence += 0.15
                break
        
        # Boost confidence for entity extraction
        if entities['ips']:
            confidence += 0.1
        if entities['threats']:
            confidence += 0.15
        if entities['time_range']:
            confidence += 0.1
        if entities['mitre_techniques']:
            confidence += 0.2
        if entities['severity']:
            confidence += 0.1
        
        # Special boosts for specific intents
        if intent_type == 'report' and any(word in query for word in ['generate', 'create', 'summary']):
            confidence += 0.15
        
        return min(confidence, 1.0)
    
    def _generate_elasticsearch_query(self, intent: QueryIntent) -> Dict:
        """Convert intent to Elasticsearch DSL"""
        try:
            query_body = {
                "query": {
                    "bool": {
                        "must": [],
                        "filter": [],
                        "should": []
                    }
                },
                "size": intent.entities.get('limit', 15),
                "sort": [{"@timestamp": {"order": "desc"}}]
            }
            
            # Add time range filter
            if intent.entities.get('time_range'):
                time_filter = {
                    "range": {
                        "@timestamp": {
                            "gte": intent.entities['time_range']['gte'],
                            "lte": intent.entities['time_range']['lte']
                        }
                    }
                }
                query_body["query"]["bool"]["filter"].append(time_filter)
            
            # Add threat type filters
            if intent.entities.get('threats'):
                threat_queries = []
                for threat in intent.entities['threats']:
                    threat_query = {
                        "bool": {
                            "should": [
                                {"wildcard": {"rule.description": f"*{threat}*"}},
                                {"wildcard": {"event.type": f"*{threat}*"}},
                                {"wildcard": {"event.category": f"*{threat}*"}},
                                {"match": {"rule.description": threat}},
                                {"match": {"event.category": threat}}
                            ]
                        }
                    }
                    threat_queries.append(threat_query)
                
                query_body["query"]["bool"]["must"].append({
                    "bool": {"should": threat_queries, "minimum_should_match": 1}
                })
            
            # Add aggregations for reports and aggregates
            if intent.intent_type in ['report', 'aggregate']:
                query_body["aggs"] = self._generate_aggregations(intent)
                if intent.intent_type == 'report':
                    query_body["size"] = 50  # More data for reports
            
            # If no specific filters, add basic security event matching
            if (not query_body["query"]["bool"]["must"] and 
                not query_body["query"]["bool"]["filter"]):
                query_body["query"] = {"match_all": {}}
            
            return query_body
            
        except Exception as e:
            logger.error(f"Error generating Elasticsearch query: {e}")
            return {"query": {"match_all": {}}, "size": 15}
    
    def _generate_aggregations(self, intent: QueryIntent) -> Dict:
        """Generate aggregations for aggregate intent types"""
        aggs = {
            "events_over_time": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "1h"
                }
            },
            "top_source_ips": {
                "terms": {
                    "field": "source.ip",
                    "size": 10
                }
            },
            "event_categories": {
                "terms": {
                    "field": "event.category",
                    "size": 10
                }
            },
            "severity_breakdown": {
                "terms": {
                    "field": "event.severity",
                    "size": 10
                }
            }
        }
        
        return aggs
    
    def should_use_gemini(self, query: str) -> bool:
        """Decide if query needs Gemini vs direct ES query - Very restrictive for data queries"""
        query_lower = query.lower()
        
        # STRONG data request indicators - these should NEVER go to Gemini
        strong_data_indicators = [
            'show me', 'find', 'search', 'list', 'display', 'get',
            'generate.*report', 'create.*report', 'security report',
            'malware events', 'firewall logs', 'security events',
            'threat intelligence', 'alert', 'incident'
        ]
        
        # Check for strong data request indicators first
        for indicator in strong_data_indicators:
            if re.search(indicator, query_lower):
                logger.debug(f"🚫 Blocking Gemini routing - found data indicator: {indicator}")
                return False
        
        # Educational indicators - only these go to Gemini
        educational_indicators = [
            'how to', 'what is', 'explain how', 'help me build', 'teach me',
            'tutorial', 'best practice', 'difference between', 'compare'
        ]
        
        # Only route to Gemini for pure educational queries
        for indicator in educational_indicators:
            if indicator in query_lower:
                logger.debug(f"✅ Routing to Gemini - found educational indicator: {indicator}")
                return True
        
        logger.debug("🔍 No clear routing indicators - defaulting to Elasticsearch")
        return False
    
    def get_query_summary(self, intent: QueryIntent) -> str:
        """Generate a human-readable summary of the parsed query"""
        summary_parts = []
        
        summary_parts.append(f"Intent: {intent.intent_type.replace('_', ' ').title()}")
        summary_parts.append(f"Confidence: {intent.confidence:.0%}")
        
        if intent.entities.get('threats'):
            summary_parts.append(f"Threats: {', '.join(intent.entities['threats'][:3])}")
        
        if intent.entities.get('time_range'):
            summary_parts.append(f"Time: {intent.entities['time_range']['format']}")
        
        if intent.entities.get('ips'):
            summary_parts.append(f"IPs: {', '.join(intent.entities['ips'][:2])}")
        
        return " | ".join(summary_parts)


# Testing function
if __name__ == "__main__":
    processor = SecurityNLPProcessor()
    
    test_queries = [
        "Generate a security report for malware events",
        "Show me firewall logs from last 24 hours",
        "What is MITRE T1110 technique?",
        "Help me write a KQL query"
    ]
    
    for query in test_queries:
        print(f"\n📝 Testing: '{query}'")
        intent = processor.process_query(query)
        print(f"   ✅ Result: {processor.get_query_summary(intent)}")
        print(f"   🤖 Use Gemini: {processor.should_use_gemini(query)}")
