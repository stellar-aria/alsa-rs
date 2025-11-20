//! Enumerates UMP (Universal MIDI Packet) devices and displays information
//! about endpoints and function blocks.
//!
//! This demonstrates MIDI 2.0 / UMP support in ALSA.
//!
//! Note: UMP support requires Linux kernel 6.5+ with CONFIG_SND_UMP enabled and/or the snd-ump module loaded.

extern crate alsa;

use alsa::card;
use alsa::ctl::{Ctl, UmpDeviceIter};

fn main() {
    println!("UMP MIDI 2.0 Devices:");
    println!("=====================\n");

    let mut found_any_ump = false;
    let mut ump_not_supported_on_any = false;

    // Iterate over all sound cards
    for card in card::Iter::new() {
        let card = match card {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error getting card: {}", e);
                continue;
            }
        };

        let card_name = match card.get_name() {
            Ok(name) => name,
            Err(_) => format!("Card {}", card.get_index()),
        };

        // Open control interface for this card
        let ctl = match Ctl::from_card(&card, false) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Cannot open control for {}: {}", card_name, e);
                continue;
            }
        };

        let mut has_ump = false;
        let mut ump_not_supported = false;

        // Enumerate UMP devices on this card
        for ump_info in UmpDeviceIter::new(&ctl) {
            let ump_info = match ump_info {
                Ok(info) => info,
                Err(e) => {
                    // ENOTTY (25) means the kernel doesn't support UMP
                    // This is expected on kernels without MIDI 2.0 support
                    if e.errno() == libc::ENOTTY {
                        ump_not_supported = true;
                        break;
                    }
                    eprintln!("Error getting UMP info: {}", e);
                    continue;
                }
            };

            if !has_ump {
                println!("Card: {}", card_name);
                has_ump = true;
            }

            println!("  UMP Device {}", ump_info.get_device());
            
            if let Ok(name) = ump_info.get_name() {
                println!("    Name: {}", name);
            }

            if let Ok(product_id) = ump_info.get_product_id() {
                if !product_id.is_empty() {
                    println!("    Product ID: {}", product_id);
                }
            }

            println!("    Version: 0x{:04x}", ump_info.get_version());
            println!("    Protocol Caps: 0x{:08x}", ump_info.get_protocol_caps());
            println!("    Protocol: 0x{:08x}", ump_info.get_protocol());
            println!("    Manufacturer ID: 0x{:08x}", ump_info.get_manufacturer_id());
            println!("    Family ID: 0x{:04x}", ump_info.get_family_id());
            println!("    Model ID: 0x{:04x}", ump_info.get_model_id());

            let sw_rev = ump_info.get_sw_revision();
            println!("    Software Revision: {}.{}.{}.{}", 
                     sw_rev[0], sw_rev[1], sw_rev[2], sw_rev[3]);

            let num_blocks = ump_info.get_num_blocks();
            println!("    Number of Function Blocks: {}", num_blocks);

            // Enumerate function blocks
            for block_id in 0..num_blocks {
                let mut block_info = match alsa::ump::UmpBlockInfo::empty() {
                    Ok(info) => info,
                    Err(e) => {
                        eprintln!("Error creating block info: {}", e);
                        continue;
                    }
                };
                
                // Set the block information for the query
                block_info.set_card(card.get_index() as u32);
                block_info.set_device(ump_info.get_device() as u32);
                block_info.set_block_id(block_id);
                
                if let Ok(_) = ctl.ump_block_info(&mut block_info) {
                    if let Ok(block_name) = block_info.get_name() {
                        println!("\n      Block {}: {}", block_id, block_name);
                    } else {
                        println!("\n      Block {}", block_id);
                    }
                    
                    println!("        Direction: {:?}", block_info.get_direction());
                    println!("        Active: {}", block_info.get_active() != 0);
                    println!("        First Group: {}", block_info.get_first_group());
                    println!("        Num Groups: {}", block_info.get_num_groups());
                    println!("        MIDI CI Version: 0x{:02x}", block_info.get_midi_ci_version());
                    println!("        SysEx8 Streams: {}", block_info.get_sysex8_streams());
                    println!("        UI Hint: {:?}", block_info.get_ui_hint());
                }
            }

            println!();
        }

        if has_ump {
            found_any_ump = true;
            println!();
        }
        
        if ump_not_supported {
            ump_not_supported_on_any = true;
        }
    }

    if !found_any_ump {
        if ump_not_supported_on_any {
            println!("No UMP devices found.");
            println!("\nNote: Your kernel does not appear to support UMP (MIDI 2.0).");
            println!("UMP support requires Linux kernel 6.5+ with CONFIG_SND_UMP enabled.");
        } else {
            println!("No UMP devices found.");
        }
    }
}
