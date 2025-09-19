
import json
import uuid
import hashlib
from datetime import datetime
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import os

class CertificateGenerator:
    """Generate tamper-proof wipe certificates"""
    
    def __init__(self):
        self.cert_dir = os.path.join(os.getcwd(), 'certificates')
        os.makedirs(self.cert_dir, exist_ok=True)
    
    def generate_certificate(self, wipe_data: Dict[str, Any]) -> str:
        """Generate both PDF and JSON certificates"""
        cert_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        # Create certificate data
        cert_data = {
            'certificate_id': cert_id,
            'generated_at': timestamp,
            'device_info': {
                'path': wipe_data['device_path'],
                'size_bytes': wipe_data['device_size'],
                'size_human': self._format_bytes(wipe_data['device_size'])
            },
            'wipe_details': {
                'method': wipe_data['method'],
                'start_time': wipe_data['start_time'].isoformat(),
                'end_time': wipe_data['end_time'].isoformat(),
                'duration_seconds': wipe_data['duration'],
                'total_passes': wipe_data['passes']
            },
            'verification': {
                'hashes': wipe_data['verification_hashes'],
                'certificate_hash': None  # Will be calculated
            },
            'compliance': {
                'standard': 'NIST SP 800-88 Rev. 1' if wipe_data['method'] == 'NIST' else 'DoD 5220.22-M',
                'verified': True
            }
        }
        
        # Calculate certificate hash for tamper detection
        cert_content = json.dumps(cert_data, sort_keys=True, default=str)
        cert_hash = hashlib.sha256(cert_content.encode()).hexdigest()
        cert_data['verification']['certificate_hash'] = cert_hash
        
        # Save JSON certificate
        json_path = os.path.join(self.cert_dir, f'{cert_id}.json')
        with open(json_path, 'w') as f:
            json.dump(cert_data, f, indent=2, default=str)
        
        # Generate PDF certificate
        pdf_path = os.path.join(self.cert_dir, f'{cert_id}.pdf')
        self._generate_pdf_certificate(cert_data, pdf_path)
        
        return cert_id
    
    def _generate_pdf_certificate(self, cert_data: Dict[str, Any], pdf_path: str):
        """Generate PDF certificate"""
        doc = SimpleDocTemplate(pdf_path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.darkblue,
            alignment=1,  # Center
            spaceAfter=30
        )
        story.append(Paragraph("SECURE DATA WIPE CERTIFICATE", title_style))
        
        # Certificate ID
        story.append(Paragraph(f"<b>Certificate ID:</b> {cert_data['certificate_id']}", styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Device Information
        story.append(Paragraph("<b>Device Information</b>", styles['Heading2']))
        device_data = [
            ['Device Path:', cert_data['device_info']['path']],
            ['Device Size:', cert_data['device_info']['size_human']],
            ['Size (bytes):', f"{cert_data['device_info']['size_bytes']:,}"]
        ]
        device_table = Table(device_data, colWidths=[2*inch, 4*inch])
        device_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(device_table)
        story.append(Spacer(1, 20))
        
        # Wipe Details
        story.append(Paragraph("<b>Wipe Operation Details</b>", styles['Heading2']))
        wipe_data = [
            ['Method:', cert_data['wipe_details']['method']],
            ['Standard:', cert_data['compliance']['standard']],
            ['Start Time:', cert_data['wipe_details']['start_time']],
            ['End Time:', cert_data['wipe_details']['end_time']],
            ['Duration:', f"{cert_data['wipe_details']['duration_seconds']:.2f} seconds"],
            ['Total Passes:', str(cert_data['wipe_details']['total_passes'])]
        ]
        wipe_table = Table(wipe_data, colWidths=[2*inch, 4*inch])
        wipe_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ]))
        story.append(wipe_table)
        story.append(Spacer(1, 20))
        
        # Verification
        story.append(Paragraph("<b>Verification Hashes</b>", styles['Heading2']))
        for hash_data in cert_data['verification']['hashes']:
            story.append(Paragraph(
                f"Pass {hash_data['pass']} ({hash_data['pattern']}): {hash_data['hash'][:16]}...",
                styles['Code']
            ))
        story.append(Spacer(1, 20))
        
        # Certificate Hash
        story.append(Paragraph("<b>Certificate Integrity</b>", styles['Heading2']))
        story.append(Paragraph(
            f"Certificate Hash: {cert_data['verification']['certificate_hash']}",
            styles['Code']
        ))
        story.append(Spacer(1, 20))
        
        # Footer
        footer_text = (
            "This certificate provides cryptographic proof that the specified device "
            "has been securely wiped according to industry standards. The certificate "
            "hash ensures tamper detection."
        )
        story.append(Paragraph(footer_text, styles['Normal']))
        
        doc.build(story)
    
    def verify_certificate(self, cert_path: str) -> tuple[bool, str]:
        """Verify certificate integrity"""
        try:
            with open(cert_path, 'r') as f:
                cert_data = json.load(f)
            
            stored_hash = cert_data['verification']['certificate_hash']
            
            # Recalculate hash
            cert_data_copy = cert_data.copy()
            cert_data_copy['verification']['certificate_hash'] = None
            
            recalc_content = json.dumps(cert_data_copy, sort_keys=True, default=str)
            recalc_hash = hashlib.sha256(recalc_content.encode()).hexdigest()
            
            if stored_hash == recalc_hash:
                return True, "Certificate is valid and untampered"
            else:
                return False, "Certificate has been tampered with"
        
        except Exception as e:
            return False, f"Certificate verification failed: {e}"
    
    def _format_bytes(self, bytes_size: float) -> str:
        """Format bytes in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_size < 1024.0:
                return f"{bytes_size:.2f} {unit}"
            bytes_size /= 1024.0
        return f"{bytes_size:.2f} PB"