use std::fs::{create_dir_all, remove_file, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use filecoin_proofs::fr32::{
    almost_truncate_to_unpadded_bytes, target_unpadded_bytes, write_padded,
};
use filecoin_proofs::types::*;

use crate::error::SectorManagerErr;
use crate::store::{ProofsConfig, SectorConfig, SectorManager, SectorStore};
// use crate::util;

// These sizes are for SEALED sectors. They are used to calculate the values of setup parameters.
// They can be overridden by setting the corresponding environment variable (with FILECOIN_PROOFS_ prefix),
// but this is not recommended, since some sealed sector sizes are invalid. If you must set this manually,
// ensure the chosen sector size is a multiple of 32.


// These sizes are for SEALED sectors. They are used to calculate the values of setup parameters.
// They can be overridden by setting the corresponding environment variable (with FILECOIN_PROOFS_ prefix),
// but this is not recommended, since some sealed sector sizes are invalid. If you must set this manually,
// ensure the chosen sector size is a multiple of 32.


// This is a segmented sectorid expression protocol, to support meaningful sector name on disk
// See: https://github.com/filecoin-project/rust-fil-proofs/issues/620 for the details
// Currently, only the default one - on (original) and an IP example design are supported, 
// To create a mechanism to support future extension
pub enum SectorAccessProto {
    // complicant with the original design, only the lower 32bit is used for sectorId index for a casual miner
    // The sector_access_name is like: on-000000000000-dddddddddd
    On(u32),   // Here the parameter is the segment index, set to 0 by default

    // an example for extension using IP address of NAS storage
    // The sector_access_name is like: ip-192168001010-dddddddddd
    Ip(String),  // Here the parameter is the IP string, as "192168001010"

    // Leave for future protocol extension, e.g. 
    // Uuid(String, u32),     // to indicate a media with UUID   
}

pub struct DiskManager {
    staging_path: String,
    sealed_path: String,

    // A sector ID presentation with a defined protocol
    sector_access_proto: SectorAccessProto, 
    sector_segment_id: u32,
}

impl SectorManager for DiskManager {
    fn new_sealed_sector_access(&self, sector_id: SectorId) -> Result<String, SectorManagerErr> {
        self.new_sector_access(Path::new(&self.sealed_path), sector_id)
    }

    fn new_staging_sector_access(&self, sector_id: SectorId) -> Result<String, SectorManagerErr> {
        self.new_sector_access(Path::new(&self.staging_path), sector_id)
    }

    fn num_unsealed_bytes(&self, access: &str) -> Result<u64, SectorManagerErr> {
        OpenOptions::new()
            .read(true)
            .open(access)
            .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
            .map(|mut f| {
                target_unpadded_bytes(&mut f)
                    .map_err(|err| SectorManagerErr::ReceiverError(format!("{:?}", err)))
            })
            .and_then(|n| n)
    }

    fn truncate_unsealed(&self, access: &str, size: u64) -> Result<(), SectorManagerErr> {
        // I couldn't wrap my head around all ths result mapping, so here it is all laid out.
        match OpenOptions::new().write(true).open(&access) {
            Ok(mut file) => match almost_truncate_to_unpadded_bytes(&mut file, size) {
                Ok(padded_size) => match file.set_len(padded_size as u64) {
                    Ok(_) => Ok(()),
                    Err(err) => Err(SectorManagerErr::ReceiverError(format!("{:?}", err))),
                },
                Err(err) => Err(SectorManagerErr::ReceiverError(format!("{:?}", err))),
            },
            Err(err) => Err(SectorManagerErr::CallerError(format!("{:?}", err))),
        }
    }

    // TODO: write_and_preprocess should refuse to write more data than will fit. In that case, return 0.
    fn write_and_preprocess(
        &self,
        access: &str,
        data: &mut dyn Read,
    ) -> Result<UnpaddedBytesAmount, SectorManagerErr> {
        OpenOptions::new()
            .read(true)
            .write(true)
            .open(access)
            .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
            .and_then(|mut file| {
                write_padded(data, &mut file)
                    .map_err(|err| SectorManagerErr::ReceiverError(format!("{:?}", err)))
                    .map(|n| UnpaddedBytesAmount(n as u64))
            })
    }

    fn delete_staging_sector_access(&self, access: &str) -> Result<(), SectorManagerErr> {
        remove_file(access).map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
    }

    fn read_raw(
        &self,
        access: &str,
        start_offset: u64,
        num_bytes: UnpaddedBytesAmount,
    ) -> Result<Vec<u8>, SectorManagerErr> {
        OpenOptions::new()
            .read(true)
            .open(access)
            .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))
            .and_then(|mut file| -> Result<Vec<u8>, SectorManagerErr> {
                file.seek(SeekFrom::Start(start_offset))
                    .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))?;

                let mut buf = vec![0; usize::from(num_bytes)];

                file.read_exact(buf.as_mut_slice())
                    .map_err(|err| SectorManagerErr::CallerError(format!("{:?}", err)))?;

                Ok(buf)
            })
    }
}

impl DiskManager {
    fn new_sector_access(&self, root: &Path, sector_id: SectorId) -> Result<String, SectorManagerErr> {
        // let pbuf = root.join(util::rand_alpha_string(32));
        let filename = self.convert_sector_id_to_access_name(sector_id)?;
        let pbuf = root.join(filename);

        create_dir_all(root)
            .map_err(|err| SectorManagerErr::ReceiverError(format!("{:?}", err)))
            .and_then(|_| {
                File::create(&pbuf)
                    .map(|_| 0)
                    .map_err(|err| SectorManagerErr::ReceiverError(format!("{:?}", err)))
            })
            .and_then(|_| {
                pbuf.to_str().map_or_else(
                    || {
                        Err(SectorManagerErr::ReceiverError(
                            "could not create pbuf".to_string(),
                        ))
                    },
                    |str_ref| Ok(str_ref.to_owned()),
                )
            })
    }

    fn convert_sector_id_to_access_name(&self, sector_id: SectorId) -> Result<String, SectorManagerErr> {
        let seg_id = (sector_id >> 32) as u32;
        let index = sector_id & 0x00000000ffffffff;

        match &self.sector_access_proto {
            SectorAccessProto::On(_) => {
                if seg_id != self.sector_segment_id { 
                    Err(SectorManagerErr::CallerError(format!("seg_id({}) does not match the setting({})", seg_id, self.sector_segment_id)))
                } else {
                    Ok(format!("on-{:12}-{:10}", seg_id, index))
                }
            }
            SectorAccessProto::Ip(ip_string) => {
                if seg_id != self.sector_segment_id { 
                    Err(SectorManagerErr::CallerError(format!("seg_id({}) does not match the setting({})", seg_id, self.sector_segment_id)))
                } else {
                    Ok(format!("ip-{}-{:10}", ip_string, index))
                }
            }
            // _ => Err(SectorManagerErr::UnclassifiedError(format!("The SectorAccessProto could not be recognized")))
        }
    }

    fn convert_sector_access_name_to_id(&self, filename: &str) -> Result<SectorId, SectorManagerErr> {
        let ind = self.sector_access_proto.validate_and_return_index(filename)?;

        Ok( (self.sector_segment_id as u64) << 32 + ind)
    }     
}

impl SectorAccessProto {
    // Return the sector index (the lower 32bit value) or Error when the format is incorrect
    fn validate_and_return_index(&self, filename: &str) -> Result<u32, SectorManagerErr> {
        if filename.len() != 26 { 
            Err(SectorManagerErr::CallerError(format!("The sector file name '{}' is not supported in this version", filename)))
        } else if filename.chars().nth(2).unwrap() != '-' || filename.chars().nth(15).unwrap() != '-' {
            Err(SectorManagerErr::CallerError(format!("The sector file name '{}' is not supported in this version", filename)))
        } else {
            let proto_str = &filename[..2];  
            let seg_str = &filename[3..15];
            let ind_str = &filename[16..];
            
            // TODO: error handling
            let index = ind_str.parse::<u32>().unwrap();

            match self {
                SectorAccessProto::On(seg_id) => {
                    if proto_str != "on" {
                        Err(SectorManagerErr::CallerError(format!("The worker is set to On format sector access only, the file '{}' is not.", filename)))
                    } else if seg_str != format!("{:12}", seg_id) {
                        Err(SectorManagerErr::CallerError(format!("The seg_id should be {:12}, the file '{}' is not.", seg_id, filename)))
                    } else { Ok(index) }
                }
                SectorAccessProto::Ip(addr) => {
                    if proto_str != "ip" {
                        Err(SectorManagerErr::CallerError(format!("The worker is set to Ip format sector access only, the file '{}' is not.", filename)))
                    } else if seg_str != addr {
                        Err(SectorManagerErr::CallerError(format!("The seg_id should be {}, the file '{}' is not.", addr, filename)))
                    } else { Ok(index) }
                }
            }
        }
    }
}

pub struct Config {
    pub porep_config: PoRepConfig,
    pub post_config: PoStConfig,
}

pub struct ConcreteSectorStore {
    proofs_config: Box<ProofsConfig>,
    sector_config: Box<SectorConfig>,
    manager: Box<SectorManager>,
}

impl SectorStore for ConcreteSectorStore {
    fn sector_config(&self) -> &SectorConfig {
        self.sector_config.as_ref()
    }

    fn proofs_config(&self) -> &ProofsConfig {
        self.proofs_config.as_ref()
    }

    fn manager(&self) -> &SectorManager {
        self.manager.as_ref()
    }
}

pub fn new_sector_store(
    sector_class: SectorClass,
    sealed_path: String,
    staging_path: String,
) -> ConcreteSectorStore {
    // By default, support On-000000000000-dddddddddd format
    let default_access_proto = SectorAccessProto::On(0);

    let manager = Box::new(DiskManager {
        staging_path,
        sealed_path,
        sector_access_proto: default_access_proto,
        sector_segment_id: 0u32,
    });

    let sector_config = Box::new(Config::from(sector_class));
    let proofs_config = Box::new(Config::from(sector_class));

    ConcreteSectorStore {
        proofs_config,
        sector_config,
        manager,
    }
}

impl SectorConfig for Config {
    fn max_unsealed_bytes_per_sector(&self) -> UnpaddedBytesAmount {
        UnpaddedBytesAmount::from(self.porep_config)
    }

    fn sector_bytes(&self) -> PaddedBytesAmount {
        PaddedBytesAmount::from(self.porep_config)
    }
}

impl ProofsConfig for Config {
    fn post_config(&self) -> PoStConfig {
        self.post_config
    }

    fn porep_config(&self) -> PoRepConfig {
        self.porep_config
    }
}

impl From<SectorClass> for Config {
    fn from(x: SectorClass) -> Self {
        match x {
            SectorClass(size, porep_p, post_p) => Config {
                porep_config: PoRepConfig(size, porep_p),
                post_config: PoStConfig(size, post_p),
            },
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use std::fs::{create_dir_all, File};
    use std::io::{Read, Write};

    use filecoin_proofs::constants::{LIVE_SECTOR_SIZE, TEST_SECTOR_SIZE};
    use filecoin_proofs::fr32::FR32_PADDING_MAP;
    use filecoin_proofs::types::{PoRepProofPartitions, PoStProofPartitions, SectorSize};

    use tempfile::{self, NamedTempFile};

    fn create_sector_store(sector_class: SectorClass) -> impl SectorStore {
        let staging_path = tempfile::tempdir().unwrap().path().to_owned();
        let sealed_path = tempfile::tempdir().unwrap().path().to_owned();

        create_dir_all(&staging_path).expect("failed to create staging dir");
        create_dir_all(&sealed_path).expect("failed to create sealed dir");

        new_sector_store(
            sector_class,
            sealed_path.to_str().unwrap().to_owned(),
            staging_path.to_str().unwrap().to_owned(),
        )
    }

    fn read_all_bytes(access: &str) -> Vec<u8> {
        let mut file = File::open(access).unwrap();
        let mut buf = Vec::new();
        file.read_to_end(&mut buf).unwrap();

        buf
    }

    #[test]
    fn max_unsealed_bytes_per_sector_checks() {
        let xs = vec![
            (
                SectorClass(
                    SectorSize(LIVE_SECTOR_SIZE),
                    PoRepProofPartitions(2),
                    PoStProofPartitions(1),
                ),
                266338304,
            ),
            (
                SectorClass(
                    SectorSize(TEST_SECTOR_SIZE),
                    PoRepProofPartitions(2),
                    PoStProofPartitions(1),
                ),
                1016,
            ),
        ];

        for (sector_class, num_bytes) in xs {
            let storage = create_sector_store(sector_class);
            let cfg = storage.sector_config();
            assert_eq!(u64::from(cfg.max_unsealed_bytes_per_sector()), num_bytes);
        }
    }

    #[test]
    fn unsealed_sector_write_and_truncate() {
        let storage = create_sector_store(SectorClass(
            SectorSize(TEST_SECTOR_SIZE),
            PoRepProofPartitions(2),
            PoStProofPartitions(1),
        ));
        let mgr = storage.manager();

        let access = mgr
            .new_staging_sector_access()
            .expect("failed to create staging file");

        // shared amongst test cases
        let contents = &[2u8; 500];

        // write contents to temp file and return mutable handle
        let mut file = {
            let mut file = NamedTempFile::new().expect("could not create named temp file");
            let _ = file.write_all(contents);
            let _ = file
                .seek(SeekFrom::Start(0))
                .expect("failed to seek to beginning of file");
            file
        };

        // write_and_preprocess
        {
            let n = mgr
                .write_and_preprocess(&access, &mut file)
                .expect("failed to write");

            // buffer the file's bytes into memory after writing bytes
            let buf = read_all_bytes(&access);
            let output_bytes_written = buf.len();

            // ensure that we reported the correct number of written bytes
            assert_eq!(contents.len(), usize::from(n));

            // ensure the file we wrote to contains the expected bytes
            assert_eq!(contents[0..32], buf[0..32]);
            assert_eq!(8u8, buf[32]);

            // read the file into memory again - this time after we truncate
            let buf = read_all_bytes(&access);

            // ensure the file we wrote to contains the expected bytes
            assert_eq!(504, buf.len());

            // also ensure this is the amount we calculate
            let expected_padded_bytes =
                FR32_PADDING_MAP.transform_byte_offset(contents.len(), true);
            assert_eq!(expected_padded_bytes, output_bytes_written);

            // ensure num_unsealed_bytes returns the number of data bytes written.
            let num_bytes_written = mgr
                .num_unsealed_bytes(&access)
                .expect("failed to get num bytes");
            assert_eq!(500, num_bytes_written as usize);
        }

        // truncation and padding
        {
            let xs: Vec<(usize, bool)> = vec![(32, true), (31, false), (1, false)];

            for (num_bytes, expect_fr_shift) in xs {
                mgr.truncate_unsealed(&access, num_bytes as u64)
                    .expect("failed to truncate");

                // read the file into memory again - this time after we truncate
                let buf = read_all_bytes(&access);

                // All but last bytes are identical.
                assert_eq!(contents[0..num_bytes], buf[0..num_bytes]);

                if expect_fr_shift {
                    // The last byte (first of new Fr) has been shifted by two bits of padding.
                    assert_eq!(contents[num_bytes] << 2, buf[num_bytes]);

                    // ensure the buffer contains the extra byte
                    assert_eq!(num_bytes + 1, buf.len());
                } else {
                    // no extra byte here
                    assert_eq!(num_bytes, buf.len());
                }

                // ensure num_unsealed_bytes returns the correct number post-truncation
                let num_bytes_written = mgr
                    .num_unsealed_bytes(&access)
                    .expect("failed to get num bytes");
                assert_eq!(num_bytes, num_bytes_written as usize);
            }
        }
    }

    #[test]
    fn deletes_staging_access() {
        let store = create_sector_store(SectorClass(
            SectorSize(TEST_SECTOR_SIZE),
            PoRepProofPartitions(2),
            PoStProofPartitions(1),
        ));
        let access = store.manager().new_staging_sector_access().unwrap();

        assert!(store
            .manager()
            .read_raw(&access, 0, UnpaddedBytesAmount(0))
            .is_ok());

        assert!(store
            .manager()
            .delete_staging_sector_access(&access)
            .is_ok());

        assert!(store
            .manager()
            .read_raw(&access, 0, UnpaddedBytesAmount(0))
            .is_err());
    }
}
