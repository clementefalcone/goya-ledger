use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::storage::traits::BlockStore;

use super::types::{ContractTemplate, LexContract};

#[derive(Clone)]
pub struct LexChainStore {
    backend: Arc<dyn BlockStore>,
    templates: Arc<Mutex<HashMap<String, ContractTemplate>>>,
}

impl LexChainStore {
    pub fn new() -> Self {
        let store = Self {
            backend: Arc::new(crate::storage::MemoryStore::new()),
            templates: Arc::new(Mutex::new(HashMap::new())),
        };
        store.register_builtins();
        store
    }

    pub fn with_backend(backend: Arc<dyn BlockStore>) -> Self {
        let store = Self {
            backend,
            templates: Arc::new(Mutex::new(HashMap::new())),
        };
        store.register_builtins();
        store
    }

    fn register_builtins(&self) {
        use super::types::RoleTemplate;
        use crate::signature::SignatureLevel;

        self.register_template(ContractTemplate {
            name: "nda".into(),
            contract_type: "non_disclosure_agreement".into(),
            roles: vec![
                RoleTemplate {
                    role: "discloser".into(),
                    signature_level: SignatureLevel::Simple,
                },
                RoleTemplate {
                    role: "recipient".into(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            require_notarization: false,
            deadline_secs: Some(604800), // 7 days
        });

        self.register_template(ContractTemplate {
            name: "service_agreement".into(),
            contract_type: "service_agreement".into(),
            roles: vec![
                RoleTemplate {
                    role: "provider".into(),
                    signature_level: SignatureLevel::Simple,
                },
                RoleTemplate {
                    role: "client".into(),
                    signature_level: SignatureLevel::Simple,
                },
            ],
            require_notarization: true,
            deadline_secs: Some(259200), // 72h
        });

        self.register_template(ContractTemplate {
            name: "power_of_attorney".into(),
            contract_type: "power_of_attorney".into(),
            roles: vec![
                RoleTemplate {
                    role: "grantor".into(),
                    signature_level: SignatureLevel::Advanced,
                },
                RoleTemplate {
                    role: "attorney".into(),
                    signature_level: SignatureLevel::Advanced,
                },
            ],
            require_notarization: true,
            deadline_secs: Some(172800), // 48h
        });
    }

    pub fn register_template(&self, template: ContractTemplate) {
        self.templates
            .lock()
            .unwrap()
            .insert(template.name.clone(), template);
    }

    pub fn get_template(&self, name: &str) -> Option<ContractTemplate> {
        self.templates.lock().unwrap().get(name).cloned()
    }

    pub fn list_templates(&self) -> Vec<ContractTemplate> {
        self.templates.lock().unwrap().values().cloned().collect()
    }

    pub fn save(&self, contract: LexContract) -> crate::storage::errors::StorageResult<()> {
        self.backend.write_lexcontract(&contract)
    }

    pub fn get(&self, id: &str) -> Option<LexContract> {
        self.backend.read_lexcontract(id).ok()
    }

    pub fn list(&self) -> Vec<LexContract> {
        self.backend.list_lexcontracts().unwrap_or_default()
    }

    pub fn backend(&self) -> &dyn BlockStore {
        &*self.backend
    }
}

impl Default for LexChainStore {
    fn default() -> Self {
        Self::new()
    }
}
