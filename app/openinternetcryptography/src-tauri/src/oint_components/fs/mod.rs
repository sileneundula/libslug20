//! # File System
//! 
//! - [ ] Keys Storage (user directory/openinternet)
//! 
//! 
//! - [ ] Folder Structure
//!     - [X] .openinternetkeys
//!         - [X] Trusted
//!         - [X] Identities
//!         - [X] Personal
//!         - [X] Resolver
//!         - [X] Logs

use dirs::home_dir;
use std::path::{PathBuf, Path};
use std::fs;
use crate::oint_components::constants::{FOLDER_CONFIG, FOLDER_IDENTITY, FOLDER_LOGS, FOLDER_PERSONAL, FOLDER_RESOLVER, FOLDER_TRUSTED};

use super::constants::FILE_NAME;

#[derive(Debug)]
pub struct Directories {
    pub root: PathBuf,
    
    pub trusted: PathBuf,
    pub personal: PathBuf,
    pub identities: PathBuf,
    pub resolvers: PathBuf,
    pub logs: PathBuf,
    pub config: PathBuf,
}

impl Directories {
    pub fn new() -> Self {
        let mut x = home_dir().unwrap();

        x.push(FILE_NAME);

        let root = x.clone();
        
        x.push(FOLDER_TRUSTED);

        let trusted = x.clone();

        x.pop();
        x.push(FOLDER_PERSONAL);

        let personal = x.clone();

        x.pop();
        x.push(FOLDER_CONFIG);

        let config = x.clone();

        x.pop();
        x.push(FOLDER_LOGS);

        let logs = x.clone();

        x.pop();
        x.push(FOLDER_IDENTITY);

        let identity = x.clone();

        x.pop();
        x.push(FOLDER_RESOLVER);

        let resolver = x.clone();



        return Self {
            root: root,
            trusted: trusted,
            personal: personal,
            identities: identity,
            config: config,
            logs: logs,
            resolvers: resolver,
        }
    }
    pub fn init(&self) {
        fs::create_dir(&self.root);
        fs::create_dir(&self.trusted);
        fs::create_dir(&self.resolvers);
        fs::create_dir(&self.personal);
        fs::create_dir(&self.config);
        fs::create_dir(&self.logs);
    }
}


pub struct CreateDirectories;

impl CreateDirectories {
    pub fn new() -> Directories {
        let mut key_path = home_dir().unwrap();

        // .openinternetcryptography
        key_path.push(FILE_NAME);

        let root_path = key_path.clone();

        // Create directory
        fs::create_dir(&key_path);

        key_path.push(FOLDER_TRUSTED);

        let trusted_folder = key_path.clone();

        fs::create_dir(&key_path);

        let mut identities = root_path.clone();

        identities.push(FOLDER_IDENTITY);

        fs::create_dir(&identities);

        let mut personal = root_path.clone();

        personal.push(FOLDER_PERSONAL);

        fs::create_dir(&personal);

        let mut resolver = root_path.clone();

        resolver.push(FOLDER_RESOLVER);
        
        fs::create_dir(&resolver);

        let mut logs = root_path.clone();
        logs.push(FOLDER_LOGS);

        fs::create_dir(&logs);

        let mut config = root_path.clone();
        config.push(FOLDER_CONFIG);

        fs::create_dir(&config);

        return Directories {
            root: root_path,
            trusted: trusted_folder,
            personal: personal,
            identities: identities,
            resolvers: resolver,
            logs: logs,
            config: config,
        }

    }
}

#[test]
fn create() {
    let x = Directories::new();
    println!("{:?}",x);
}