-- Tenants
INSERT INTO tenants (slug, name, icao_prefix, plan) VALUES
('elal',   'EL AL',   'ELY', 'enterprise'),
('israir', 'Israir',  'ISR', 'pro'),
('arkia',  'Arkia',   'AIZ', 'pro');

-- Users (password_hash = bcrypt('shadow123', 10))
-- Pre-computed bcrypt hash for 'shadow123':
INSERT INTO users (tenant_id, username, email, password_hash, role) VALUES
(1, 'elal_admin',    'admin@elal.co.il',       '$2b$10$K9XaBbGzZmNsYRVPlOqLq.FuYEJT.ZLn0KqxCdCBSoH4VV2pI3aMm', 'admin'),
(1, 'elal_analyst',  'analyst@elal.co.il',     '$2b$10$K9XaBbGzZmNsYRVPlOqLq.FuYEJT.ZLn0KqxCdCBSoH4VV2pI3aMm', 'analyst'),
(2, 'israir_admin',  'admin@israir.co.il',     '$2b$10$K9XaBbGzZmNsYRVPlOqLq.FuYEJT.ZLn0KqxCdCBSoH4VV2pI3aMm', 'admin'),
(3, 'arkia_admin',   'admin@arkia.co.il',      '$2b$10$K9XaBbGzZmNsYRVPlOqLq.FuYEJT.ZLn0KqxCdCBSoH4VV2pI3aMm', 'admin');

-- EL AL Assets (aircraft fleet)
INSERT INTO assets (tenant_id, name, asset_type, icao24, callsign, registration, status, threat_level,
  latitude, longitude, altitude_ft, speed_kts, heading, squawk, location, criticality) VALUES
(1,'EL AL 747-400','aircraft','4XELD','ELY001','4X-ELD','active','safe',        32.011,34.886,35000,520,270,'2471','Ben Gurion (TLV)',0.95),
(1,'EL AL 777-200','aircraft','4XECA','ELY002','4X-ECA','active','warning',     32.012,34.887,38000,510,090,'1200','Approach TLV',    0.95),
(1,'EL AL 787-9',  'aircraft','4XEDF','ELY003','4X-EDF','active','critical',    31.800,34.500,36000,530,180,'7700','Mediterranean',   0.98),
(1,'ADS-B Sensor TLV-1','adsb_sensor','','','','active','safe',32.005,34.880,0,0,0,'','Terminal A',0.90),
(1,'ACARS Gateway',      'gateway',    '','','','active','elevated',32.008,34.882,0,0,0,'','ATC Tower',0.98);

-- Israir Assets
INSERT INTO assets (tenant_id, name, asset_type, icao24, callsign, registration, status, threat_level,
  latitude, longitude, altitude_ft, speed_kts, heading, squawk, location, criticality) VALUES
(2,'Israir A320','aircraft','4XABD','ISR101','4X-ABD','active','safe',    32.005,34.880,32000,450,315,'1200','Ben Gurion',   0.85),
(2,'Israir A330','aircraft','4XABE','ISR102','4X-ABE','active','critical',31.900,34.700,34000,480,045,'7500','South of TLV', 0.88);

-- Arkia Assets
INSERT INTO assets (tenant_id, name, asset_type, icao24, callsign, registration, status, threat_level,
  latitude, longitude, altitude_ft, speed_kts, heading, squawk, location, criticality) VALUES
(3,'Arkia E195','aircraft','4XBAA','AIZ201','4X-BAA','active','safe',        32.008,34.882,30000,420,270,'1200','Ben Gurion',0.82),
(3,'Arkia E190','aircraft','4XBAB','AIZ202','4X-BAB','active','under_attack',32.100,34.900,28000,400,135,'7700','North of TLV',0.80);

-- Threats
INSERT INTO threats (tenant_id, asset_id, threat_type, severity, source_ip, icao24, score, description, mitre_technique, status) VALUES
(1,1,'ADS-B Spoofing',   'critical',  '192.168.1.45',   '4XELD',0.96,'Ghost aircraft injected near EL AL 747 on final approach', 'T0475','active'),
(1,2,'ACARS Injection',  'high',      '10.0.0.23',      '4XECA',0.87,'Unauthorised uplink TELEX H1 – bomb threat keyword detected','T0485','investigating'),
(1,3,'GPS Jamming',      'medium',    '172.16.8.9',     '4XEDF',0.71,'Signal degradation on 3 GPS receivers simultaneously',       'T0470','active'),
(1,5,'Radar Spoofing',   'emergency', '192.168.50.10',  '',     0.99,'Primary radar return masked – wide-area jamming suspected',   'T0471','active'),
(2,6,'Mode S Hijack',    'critical',  '192.168.10.200', '4XABD',0.94,'Squawk 7500 detected on Israir A320 non-emergency flight',   'T0475','active'),
(2,7,'CPDLC Spoofing',   'high',      '10.10.1.99',     '4XABE',0.88,'Fake ATC clearance issued via CPDLC channel',                'T0485','active'),
(3,8,'GPS Spoofing',     'high',      '45.33.22.11',    '4XBAA',0.89,'False position data injected – aircraft off published route','T0470','active'),
(3,9,'VDL Injection',    'critical',  '172.16.99.5',    '4XBAB',0.95,'Malformed X.25 frame targeting VDL ground station',          'T0471','active');

-- Alerts
INSERT INTO alerts (tenant_id, asset_id, title, severity, message) VALUES
(1,1,'Emergency squawk 7700 – EL AL 747',     'emergency','EL AL 747 declared emergency via ADS-B squawk 7700'),
(1,2,'ACARS bomb threat keyword detected',     'critical', 'Keyword [bomb] in uplink message H1 – verify immediately'),
(1,3,'GPS degradation – 3 receivers offline',  'high',     '3 GPS receivers reporting signal loss simultaneously'),
(2,6,'Hijack squawk 7500 – Israir A320',       'critical', 'Possible hijack in progress – immediate response required'),
(2,7,'CPDLC clearance mismatch',               'high',     'Issued clearance does not match ATC records – possible spoofing'),
(3,8,'False GPS data on Arkia E195',           'high',     'Aircraft reporting position 12nm off track'),
(3,9,'Arkia E190 under active attack',         'emergency','VDL injection detected – aircraft communications compromised');

-- Risk scores
INSERT INTO risk_scores (tenant_id, asset_id, entity_name, risk_score, threat_types) VALUES
(1,1,'EL AL 747 (4X-ELD)', 95.4,ARRAY['ADS-B Spoofing']),
(1,2,'EL AL 777 (4X-ECA)', 87.2,ARRAY['ACARS Injection']),
(1,3,'EL AL 787 (4X-EDF)', 71.0,ARRAY['GPS Jamming']),
(2,6,'Israir A320 (4X-ABD)',94.0,ARRAY['Mode S Hijack']),
(2,7,'Israir A330 (4X-ABE)',88.0,ARRAY['CPDLC Spoofing']),
(3,8,'Arkia E195 (4X-BAA)', 89.0,ARRAY['GPS Spoofing']),
(3,9,'Arkia E190 (4X-BAB)', 95.0,ARRAY['VDL Injection']);

-- Audit log seeds
INSERT INTO audit_log (tenant_id, user_id, action, resource, details) VALUES
(1,1,'USER_LOGIN',      'session', '{"ip":"10.0.0.1"}'),
(1,1,'THREAT_VIEWED',   'threat',  '{"threat_type":"ADS-B Spoofing"}'),
(1,2,'ALERT_ACK',       'alert',   '{"alert_id":1}');
