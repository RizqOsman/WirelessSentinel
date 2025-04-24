from app import db
from datetime import datetime

class Network(db.Model):
    """Model for storing information about detected networks"""
    id = db.Column(db.Integer, primary_key=True)
    bssid = db.Column(db.String(17), nullable=False, index=True)
    ssid = db.Column(db.String(32), nullable=True)
    channel = db.Column(db.Integer, nullable=True)
    signal_strength = db.Column(db.Integer, nullable=True)
    security = db.Column(db.String(32), nullable=True)
    encryption = db.Column(db.String(32), nullable=True)
    is_weak = db.Column(db.Boolean, default=False)
    is_rogue = db.Column(db.Boolean, default=False)
    first_seen = db.Column(db.DateTime, default=datetime.utcnow)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<Network {self.ssid} ({self.bssid})>"

class BruteForceAttempt(db.Model):
    """Model for storing information about brute force attempts"""
    id = db.Column(db.Integer, primary_key=True)
    bssid = db.Column(db.String(17), nullable=False, index=True)
    ssid = db.Column(db.String(32), nullable=True)
    security_type = db.Column(db.String(32), nullable=False)
    wordlist_path = db.Column(db.String(255), nullable=True)
    passwords_tried = db.Column(db.Integer, default=0)
    successful = db.Column(db.Boolean, default=False)
    password_found = db.Column(db.String(255), nullable=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<BruteForceAttempt {self.ssid} ({self.bssid})>"

class DeauthEvent(db.Model):
    """Model for storing information about deauthentication events"""
    id = db.Column(db.Integer, primary_key=True)
    bssid = db.Column(db.String(17), nullable=False, index=True)
    ssid = db.Column(db.String(32), nullable=True)
    client_mac = db.Column(db.String(17), nullable=True)
    count = db.Column(db.Integer, default=1)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<DeauthEvent {self.ssid} ({self.bssid})>"
