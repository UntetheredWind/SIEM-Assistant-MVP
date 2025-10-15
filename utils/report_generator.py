import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import logging
import re
import random

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Unified report generator for all formats"""
    
    def __init__(self, gemini_client):
        self.gemini_client = gemini_client
        logger.info("ReportGenerator initialized")
        
        self.format_keywords = {
            'graphical': [
                'chart', 'graph', 'plot', 'visualization', 'visualize', 'visual',
                'pie', 'bar', 'line', 'timeline', 'histogram', 'scatter'
            ],
            'tabular': [
                'table', 'list', 'breakdown', 'csv', 'dataframe', 'rows',
                'columns', 'spreadsheet', 'export'
            ],
            'textual': [
                'report', 'summary', 'analysis', 'narrative', 'description',
                'explain', 'overview', 'assessment', 'findings'
            ]
        }
        
        self.chart_mappings = {
            'pie': ['pie', 'distribution', 'percentage', 'proportion'],
            'bar': ['bar', 'count', 'comparison', 'top', 'bottom'],
            'line': ['line', 'trend', 'over time', 'timeline', 'temporal'],
            'scatter': ['scatter', 'correlation', 'relationship']
        }
    
    def generate_report(self, query: str, es_data: Dict) -> Dict:
        """Main entry - generates appropriate report format"""
        try:
            logger.info(f"📊 Generating report for query: '{query[:50]}...'")
            format_spec = self._detect_format(query)
            logger.info(f"🎯 Detected formats: {format_spec}")
            
            report = {
                'format': format_spec['primary_format'],
                'textual': None,
                'tabular': None,
                'chart': None,
                'metadata': {
                    'query': query,
                    'generated_at': datetime.now().isoformat(),
                    'total_records': es_data.get('total_hits', 0),
                    'query_time_ms': es_data.get('took', 0)
                }
            }
            
            # Generate textual report (always for reports)
            if format_spec['needs_text'] or 'report' in query.lower():
                logger.info("📝 Generating textual report...")
                report['textual'] = self._generate_text_report(query, es_data)
            
            # Generate tabular report
            if format_spec['needs_table'] or format_spec['primary_format'] == 'tabular':
                logger.info("📊 Generating tabular report...")
                report['tabular'] = self._generate_table_report(es_data)
            
            # Generate chart
            if format_spec['needs_chart'] or 'chart' in query.lower() or 'visual' in query.lower():
                logger.info("📈 Generating chart...")
                report['chart'] = self._generate_chart(es_data, format_spec['chart_type'])
            
            logger.info(f"✅ Report generated successfully: text={report['textual'] is not None}, table={report['tabular'] is not None}, chart={report['chart'] is not None}")
            return report
            
        except Exception as e:
            logger.error(f"❌ Error generating report: {e}")
            return {
                'format': 'error',
                'textual': f"**Report Generation Error**\n\nUnable to generate comprehensive report: {str(e)}\n\nQuery: {query}",
                'tabular': None,
                'chart': None,
                'metadata': {'error': str(e)}
            }
    
    def _detect_format(self, query: str) -> Dict:
        """Detect what format user requested"""
        query_lower = query.lower()
        
        format_scores = {'graphical': 0, 'tabular': 0, 'textual': 0}
        
        # Score each format based on keywords
        for format_type, keywords in self.format_keywords.items():
            for keyword in keywords:
                if keyword in query_lower:
                    format_scores[format_type] += 1
        
        # Determine chart type
        chart_type = 'bar'  # default
        for chart, keywords in self.chart_mappings.items():
            for keyword in keywords:
                if keyword in query_lower:
                    chart_type = chart
                    break
        
        # Special handling for security reports
        if 'report' in query_lower:
            format_scores['textual'] += 2
            format_scores['tabular'] += 1
            if 'chart' in query_lower or 'visual' in query_lower:
                format_scores['graphical'] += 2
        
        # Determine primary format
        primary_format = max(format_scores.items(), key=lambda x: x[1])[0]
        
        # Default to comprehensive for reports
        if 'report' in query_lower and max(format_scores.values()) <= 2:
            primary_format = 'textual'
        
        return {
            'primary_format': primary_format,
            'chart_type': chart_type,
            'needs_text': format_scores['textual'] > 0 or 'report' in query_lower,
            'needs_table': format_scores['tabular'] > 0 or primary_format == 'tabular',
            'needs_chart': format_scores['graphical'] > 0 or ('report' in query_lower and 'visual' in query_lower)
        }
    
    def _generate_text_report(self, query: str, data: Dict) -> str:
        """Generate markdown narrative using Gemini"""
        try:
            summary_stats = self._extract_summary_stats(data)
            
            context = f"""
You are a cybersecurity analyst generating a professional security report.

USER QUERY: {query}

ANALYSIS DATA:
- Total Events: {summary_stats['total_events']}
- Time Period: {summary_stats['time_range']}
- Top Source IPs: {summary_stats['top_ips']}
- Event Categories: {summary_stats['event_types']}
- Severity Levels: {summary_stats['severity_levels']}
- Key Security Indicators: {summary_stats['key_findings']}

Generate a concise, professional security analysis report. Include:
1. **Executive Summary** (2-3 sentences)
2. **Key Findings** (3-4 bullet points)
3. **Threat Analysis** (brief technical details)
4. **Recommendations** (2-3 actionable items)

Keep it focused and technical. Use markdown formatting.
"""
            
            report = self.gemini_client.generate_response(
                f"Generate a professional security report analysis",
                context
            )
            
            return report if report else "**Security Analysis Report**\n\nUnable to generate detailed analysis. Please check AI connection."
            
        except Exception as e:
            logger.error(f"Error generating text report: {e}")
            return f"**Malware Security Report**\n\n**Executive Summary:** Analysis of {data.get('total_hits', 0)} security events.\n\n**Error:** {str(e)}"
    
    def _generate_table_report(self, data: Dict) -> Dict:
        """Generate pandas DataFrame and CSV string"""
        try:
            df = self._elasticsearch_to_dataframe(data)
            
            if df.empty:
                return {
                    'dataframe': pd.DataFrame({'Message': ['No security events found']}),
                    'csv_export': 'Message\nNo security events found',
                    'row_count': 0,
                    'column_count': 1
                }
            
            # Limit display rows but keep full data for CSV
            display_df = df.head(50)
            csv_export = df.to_csv(index=False)
            
            return {
                'dataframe': display_df,
                'csv_export': csv_export,
                'row_count': len(df),
                'column_count': len(df.columns)
            }
            
        except Exception as e:
            logger.error(f"Error generating table: {e}")
            return {
                'dataframe': pd.DataFrame({'Error': [f'Table generation failed: {str(e)}']}),
                'csv_export': f'Error\nTable generation failed: {str(e)}',
                'row_count': 0,
                'column_count': 1
            }
    
    def _generate_chart(self, data: Dict, chart_type: str):
        """Generate Plotly figure"""
        try:
            df = self._elasticsearch_to_dataframe(data)
            
            if df.empty:
                fig = go.Figure()
                fig.add_annotation(
                    text="No data available for visualization",
                    xref="paper", yref="paper", x=0.5, y=0.5,
                    showarrow=False, font=dict(size=16)
                )
                fig.update_layout(title="No Data Found")
                return fig
            
            if chart_type == 'pie':
                return self._create_pie_chart(df)
            elif chart_type == 'line':
                return self._create_line_chart(df)
            else:  # Default to bar chart
                return self._create_bar_chart(df)
                
        except Exception as e:
            logger.error(f"Error generating chart: {e}")
            fig = go.Figure()
            fig.add_annotation(
                text=f"Chart Error: {str(e)}",
                xref="paper", yref="paper", x=0.5, y=0.5,
                showarrow=False, font=dict(size=12, color="red")
            )
            return fig
    
    def _elasticsearch_to_dataframe(self, es_data: Dict) -> pd.DataFrame:
        """Convert ES results to pandas DataFrame"""
        try:
            results = es_data.get('results', [])
            if not results:
                return pd.DataFrame()
            
            # Flatten and normalize data
            flattened_data = []
            for result in results:
                flat_result = self._flatten_dict(result)
                flattened_data.append(flat_result)
            
            df = pd.DataFrame(flattened_data)
            return self._clean_dataframe(df)
            
        except Exception as e:
            logger.error(f"Error converting to DataFrame: {e}")
            return pd.DataFrame()
    
    def _flatten_dict(self, d: Dict, prefix: str = '') -> Dict:
        """Flatten nested dictionary"""
        items = []
        for k, v in d.items():
            new_key = f"{prefix}.{k}" if prefix else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key).items())
            else:
                items.append((new_key, v))
        return dict(items)
    
    def _clean_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Clean DataFrame for display"""
        try:
            # Remove empty columns
            df = df.dropna(axis=1, how='all')
            
            # Convert timestamps
            timestamp_cols = [col for col in df.columns if 'timestamp' in col.lower()]
            for col in timestamp_cols:
                try:
                    df[col] = pd.to_datetime(df[col])
                except:
                    pass
            
            # Sort by timestamp if available
            if '@timestamp' in df.columns:
                df = df.sort_values('@timestamp', ascending=False)
            
            return df
        except:
            return df
    
    def _create_bar_chart(self, df: pd.DataFrame):
        """Create bar chart"""
        try:
            # Find best categorical column
            categorical_cols = df.select_dtypes(include=['object']).columns
            if len(categorical_cols) > 0:
                col = categorical_cols[0]
                value_counts = df[col].value_counts().head(10)
                
                fig = px.bar(
                    x=value_counts.index,
                    y=value_counts.values,
                    title=f"Distribution of {col}",
                    labels={'x': col, 'y': 'Count'}
                )
                fig.update_layout(showlegend=False)
                return fig
            else:
                raise ValueError("No categorical data for bar chart")
        except Exception as e:
            logger.error(f"Bar chart error: {e}")
            return self._create_error_chart(str(e))
    
    def _create_pie_chart(self, df: pd.DataFrame):
        """Create pie chart"""
        try:
            categorical_cols = df.select_dtypes(include=['object']).columns
            if len(categorical_cols) > 0:
                col = categorical_cols[0]
                value_counts = df[col].value_counts().head(8)
                
                fig = px.pie(
                    values=value_counts.values,
                    names=value_counts.index,
                    title=f"Distribution of {col}"
                )
                return fig
            else:
                raise ValueError("No categorical data for pie chart")
        except Exception as e:
            return self._create_error_chart(str(e))
    
    def _create_line_chart(self, df: pd.DataFrame):
        """Create line chart"""
        try:
            timestamp_cols = [col for col in df.columns if 'timestamp' in col.lower()]
            if timestamp_cols:
                df[timestamp_cols[0]] = pd.to_datetime(df[timestamp_cols[0]])
                time_counts = df.groupby(df[timestamp_cols[0]].dt.floor('H')).size().reset_index()
                time_counts.columns = ['Time', 'Count']
                
                fig = px.line(time_counts, x='Time', y='Count', title='Events Over Time')
                return fig
            else:
                return self._create_bar_chart(df)  # Fallback
        except Exception as e:
            return self._create_error_chart(str(e))
    
    def _create_error_chart(self, error_msg: str):
        """Create error chart"""
        fig = go.Figure()
        fig.add_annotation(
            text=f"Chart Error: {error_msg}",
            xref="paper", yref="paper", x=0.5, y=0.5,
            showarrow=False, font=dict(size=12, color="red")
        )
        fig.update_layout(title="Visualization Error")
        return fig
    
    def _extract_summary_stats(self, data: Dict) -> Dict:
        """Extract summary statistics"""
        results = data.get('results', [])
        total_events = data.get('total_hits', len(results))
        
        # Extract key statistics
        ips, event_types, severities = [], [], []
        
        for result in results[:20]:
            # Extract IPs
            if 'source' in result and 'ip' in result['source']:
                ips.append(result['source']['ip'])
            elif 'clientip' in result:
                ips.append(result['clientip'])
            
            # Extract event types
            if 'event' in result:
                if 'type' in result['event']:
                    event_types.append(result['event']['type'])
                if 'severity' in result['event']:
                    severities.append(str(result['event']['severity']))
            
            # Extract from rule descriptions
            if 'rule' in result and 'description' in result['rule']:
                event_types.append(result['rule']['description'])
        
        return {
            'total_events': total_events,
            'top_ips': list(pd.Series(ips).value_counts().head(5).index) if ips else ['No IPs found'],
            'event_types': list(pd.Series(event_types).value_counts().head(3).index) if event_types else ['Various events'],
            'severity_levels': list(pd.Series(severities).value_counts().head(3).index) if severities else ['Mixed severities'],
            'time_range': 'Last 24 hours (simulated)',
            'key_findings': [
                f"Analyzed {total_events} security events",
                f"Top sources: {', '.join(list(pd.Series(ips).value_counts().head(2).index) if ips else ['N/A'])}",
                f"Query executed in {data.get('took', 50)}ms"
            ]
        }


# Test the report generator
if __name__ == "__main__":
    class MockGeminiClient:
        def generate_response(self, prompt, context):
            return "**Security Report**\n\nMock report generated successfully."
    
    generator = ReportGenerator(MockGeminiClient())
    
    mock_data = {
        'success': True,
        'total_hits': 25,
        'took': 45,
        'results': [
            {'@timestamp': '2025-10-11T20:00:00Z', 'event': {'type': 'malware'}, 'source': {'ip': '192.168.1.100'}},
            {'@timestamp': '2025-10-11T19:30:00Z', 'event': {'type': 'malware'}, 'source': {'ip': '192.168.1.101'}}
        ]
    }
    
    report = generator.generate_report("Generate security report for malware", mock_data)
    print(f"Report generated: {report['format']}")
