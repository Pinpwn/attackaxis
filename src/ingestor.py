import json
import requests
import os
from typing import Dict, List, Any, Optional
from stix2 import MemoryStore, Bundle, Filter
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

STIX_URL = "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json"
DATA_DIR = "data"
STIX_FILE = os.path.join(DATA_DIR, "enterprise-attack.json")

class MITREIngestor:
    def __init__(self, stix_url: str = STIX_URL, data_file: str = STIX_FILE):
        self.stix_url = stix_url
        self.data_file = data_file
        self.fs: Optional[MemoryStore] = None

    def download_data(self, force: bool = False):
        """Downloads MITRE STIX data if not present."""
        if not os.path.exists(DATA_DIR):
            os.makedirs(DATA_DIR)
        
        if force or not os.path.exists(self.data_file):
            logger.info(f"Downloading STIX data from {self.stix_url}...")
            response = requests.get(self.stix_url)
            response.raise_for_status()
            with open(self.data_file, 'w') as f:
                json.dump(response.json(), f)
            logger.info("Download complete.")
        else:
            logger.info(f"Using cached STIX data at {self.data_file}")

    def load_data(self):
        """Loads STIX data into MemoryStore."""
        if not os.path.exists(self.data_file):
            self.download_data()
        
        with open(self.data_file, 'r') as f:
            bundle_data = json.load(f)
            self.fs = MemoryStore(bundle_data)

    def get_techniques_for_object(self, object_name: str) -> List[Dict[str, Any]]:
        """Retrieves techniques associated with a group, campaign, or software."""
        logger.info(f"Retrieving techniques for object: {object_name}")
        if not self.fs:
            self.load_data()
            if not self.fs:
                return []

        types_to_check = ['intrusion-set', 'campaign', 'malware', 'tool']
        target_obj = None
        
        for obj_type in types_to_check:
            objs = self.fs.query([
                Filter('type', '=', obj_type),
                Filter('name', '=', object_name)
            ])
            if objs:
                target_obj = objs[0]
                break
        
        if not target_obj:
            logger.warning(f"Object '{object_name}' not found in MITRE ATT&CK.")
            return []

        relationships = self.fs.query([
            Filter('type', '=', 'relationship'),
            Filter('relationship_type', '=', 'uses'),
            Filter('source_ref', '=', target_obj.id)
        ])
        
        techniques = []
        for rel in relationships:
            if rel.target_ref.startswith('attack-pattern'):
                tech = self.fs.get(rel.target_ref)
                if tech:
                    ext_refs = getattr(tech, 'external_references', [])
                    tech_id = "unknown"
                    for ref in ext_refs:
                        if ref.get('source_name') == 'mitre-attack':
                            tech_id = ref.get('external_id')
                            break
                    
                    # Get tactics
                    tactics = []
                    kill_chain_phases = getattr(tech, 'kill_chain_phases', [])
                    for phase in kill_chain_phases:
                        if phase.get('kill_chain_name') == 'mitre-attack':
                            tactics.append(phase.get('phase_name'))
                    
                    techniques.append({
                        "id": tech_id,
                        "name": tech.name,
                        "description": getattr(tech, 'description', ''),
                        "stix_id": tech.id,
                        "tactics": tactics,
                        "data_sources": getattr(tech, 'x_mitre_data_sources', [])
                    })
        
        return techniques

    def get_object_details(self, object_name: str) -> Dict[str, Any]:
        """Retrieves details for a group, campaign, or software."""
        if not self.fs:
            self.load_data()
            if not self.fs:
                return {}

        types_to_check = ['intrusion-set', 'campaign', 'malware', 'tool']
        for obj_type in types_to_check:
            objs = self.fs.query([
                Filter('type', '=', obj_type),
                Filter('name', '=', object_name)
            ])
            if objs:
                obj = objs[0]
                return {
                    "name": obj.name,
                    "description": getattr(obj, 'description', ''),
                    "aliases": getattr(obj, 'aliases', []) if hasattr(obj, 'aliases') else getattr(obj, 'x_mitre_aliases', []),
                    "type": obj.type
                }
        return {}

    def list_available_objects(self) -> Dict[str, List[str]]:
        """Lists available groups, campaigns, and software."""
        if not self.fs:
            self.load_data()
            if not self.fs:
                return {}

        results = {
            "groups": [],
            "campaigns": [],
            "software": []
        }
        
        # Intrusion Sets (Groups)
        results["groups"] = sorted([obj.name for obj in self.fs.query([Filter('type', '=', 'intrusion-set')])])
        # Campaigns
        results["campaigns"] = sorted([obj.name for obj in self.fs.query([Filter('type', '=', 'campaign')])])
        # Malware and Tools (Software)
        malware = [obj.name for obj in self.fs.query([Filter('type', '=', 'malware')])]
        tools = [obj.name for obj in self.fs.query([Filter('type', '=', 'tool')])]
        results["software"] = sorted(list(set(malware + tools)))
        
        return results
