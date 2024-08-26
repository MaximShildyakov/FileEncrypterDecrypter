use std::collections::HashMap;
use std::io::{BufReader, BufWriter, Read, Write};
use std::num::IntErrorKind;
use local_ip_address::local_ip;

fn get_input(query: &str) -> String{
    print!("{}", query);
    std::io::stdout().flush().unwrap();

    let mut buffer = String::new();
    std::io::stdin().read_line(&mut buffer).unwrap();

    buffer.trim().to_owned()
}

fn process_file_data(data: &Vec<u8>, key: u8) -> Vec<u8>{
    let mut processed_data = Vec::with_capacity(data.len());
    for byte in data{
        processed_data.push(byte ^ key);
    }

    processed_data
}

struct FileData{
    encrypted_file: HashMap<String, u8>,
    banned_ip: HashMap<String, Vec<String>>,
    ip_attempts: HashMap<Vec<String>, u8>
}

impl FileData{
    fn new() -> FileData{
        FileData{
            encrypted_file: HashMap::new(),
            banned_ip: HashMap::new(),
            ip_attempts: HashMap::new()
        }
    }
    fn add_encrypted_file(self: &mut Self, file_name: String, key: u8){
        self.encrypted_file.insert(file_name, key);
    }

    fn add_banned_ip(self: &mut Self, file_name: String, ip: String){
        self.banned_ip
            .entry(file_name)
            .or_insert_with(Vec::new)
            .push(ip);
    }

    fn change_ip_attempts(self: &mut Self, file_name: String, ip: String){
        let key = vec![file_name.clone(), ip.clone()];

        self.ip_attempts.entry(key.clone()).and_modify(|value| {
            *value += 1;
        }).or_insert(1);

        if let Some(&attempts) = self.ip_attempts.get(&key) {
            if attempts == 3 {
                self.add_banned_ip(file_name, ip);
            }
        }
    }

}

fn main() {
    let user_ip = local_ip().expect("Can't get your ip").to_string();
    let mut encrypted_files_info = FileData::new();

    loop {
        println!("# # # # # # #");

        let input_file_name = get_input("Enter the file name to process: ");
        let input_file = match std::fs::File::open(&input_file_name){
           Ok(file) => file,
            Err(err) => {
                println!("Can't open a file \"{input_file_name}\": {err}\n");
                continue
            }
        };

        if encrypted_files_info.encrypted_file.contains_key(&input_file_name) &&
            encrypted_files_info.banned_ip.contains_key(&input_file_name) &&
            encrypted_files_info.banned_ip.get(&input_file_name).unwrap().contains(&user_ip){
            println!("Access denied\n");
            continue
        }

        let key = match get_input("Enter the key for file encryption/decryption\
            (You have only 3 attempts to decrypt the file!!!): ")
            .parse::<u8>(){
            Ok(key) => key,
            Err(err) => {
                match err.kind(){
                    IntErrorKind::Empty => println!("The key must not be empty"),
                    IntErrorKind::InvalidDigit => println!("Enter a valid number"),
                    IntErrorKind::PosOverflow => println!("The number must be in the range of 0 to 255"),
                    _ => println!("Error reading the key")
                }
                println!();
                continue
            }
        };

        if key == 0{
            println!("0 is a useless key!!!\n");
            continue
        }

        if encrypted_files_info.encrypted_file.contains_key(&input_file_name)
            && *encrypted_files_info.encrypted_file.get(&input_file_name).unwrap() != key{
            encrypted_files_info.change_ip_attempts(input_file_name.clone(), user_ip.clone());
            println!("Incorrect key. Please try again.\n");
            continue
        }


        let mut reader = BufReader::new(input_file);
        let mut input_data = Vec::new();

        if let Err(err) = reader.read_to_end(&mut input_data){
            println!("Error reading file {err}\n");
            continue
        }

        let processed_data = process_file_data(&input_data, key);
        let output_file_name = get_input("Enter the file name to output: ");

        let output_file = match std::fs::File::create(&output_file_name){
           Ok(file) => file,
            Err(err) => {
                println!("Can't create a file \"{output_file_name}\": {err}\n");
                continue
            }
        };

        if !encrypted_files_info.encrypted_file.contains_key(&input_file_name){
            encrypted_files_info.add_encrypted_file(output_file_name, key);
        }

        let mut writer = BufWriter::new(output_file);

        if let Err(err) = writer.write_all(&processed_data){
            println!("Error writing to output file: {err}\n");
            continue
        }

        println!("\n");
    }

}
