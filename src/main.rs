use crypto::aegis::aegis_128L::{Aegis128LDec, Aegis128LEnc};
use crypto::{Decrypt, Encrypt};
use std::env::args;
use std::error::Error;
use std::str::FromStr;
use std::time::Instant;

pub fn bench_enc_dec<const BUFFER_SIZE: usize, const KEY_LEN: usize, const IV_LEN: usize, E, D>(
    iters: usize,
) -> (f64, f64)
where
    E: Encrypt<KEY_LEN, IV_LEN>,
    D: Decrypt<KEY_LEN, IV_LEN>,
{
    let mut a = [0; BUFFER_SIZE];
    let mut b = [0; BUFFER_SIZE];

    let start = Instant::now();

    let mut enc = E::new([0; KEY_LEN], [0; IV_LEN]);
    for _ in 0..iters {
        enc.encrypt(&a, &mut b);
        enc.encrypt(&b, &mut a);
    }
    let end = Instant::now();

    let enc_speed = (iters * BUFFER_SIZE * 16) as f64 / (end - start).as_nanos() as f64;

    let start = Instant::now();

    let mut dec = D::new([0; KEY_LEN], [0; IV_LEN]);
    for _ in 0..iters {
        dec.decrypt(&a, &mut b);
        dec.decrypt(&b, &mut a);
    }

    let end = Instant::now();

    let dec_speed = (iters * BUFFER_SIZE * 16) as f64 / (end - start).as_nanos() as f64;

    (enc_speed, dec_speed)
}

macro_rules! bench_aead {
    ($name:literal => $loc:path > $enc:ty | $dec:ty = $data:expr , $bufsize:literal) => {{
        use $loc::*;
        let (enc_speed, dec_speed) =
            $crate::bench_enc_dec::<$bufsize, KEY_LEN, IV_LEN, $enc, $dec>($data / $bufsize);
        println!("{} Encryption speed: {enc_speed} Gbps, Decryption speed: {dec_speed} Gbps", $name);
    }};
    ($name:literal => $loc:path > $enc:ty | $dec:ty = $data:expr) => {
        bench_aead!($name => $loc > $enc | $dec = $data , 8192)
    };
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut input: Vec<String> = args().skip(1).collect();

    if input.len() == 1 && input[0] == "-all" {
        input = vec![
            "aegis128".to_string(),
            "aegis256".to_string(),
            "aegis128L".to_string(),
            "aegis128X2".to_string(),
            "aegis128X4".to_string(),
            "aegis256X2".to_string(),
            "aegis256X4".to_string(),
        ];
    }

    let data_input = input
        .iter()
        .filter(|frag| frag.starts_with("data="))
        .map(|frag| &frag[5..])
        .next();

    let data = match data_input {
        None => 10 << 30,
        Some(amount) => {
            if amount.ends_with('K') {
                usize::from_str(&amount[..amount.len() - 1])? << 10
            } else if amount.ends_with('M') {
                usize::from_str(&amount[..amount.len() - 1])? << 20
            } else if amount.ends_with('G') {
                usize::from_str(&amount[..amount.len() - 1])? << 30
            } else {
                usize::from_str(&amount[..amount.len()])?
            }
        }
    };

    let friendly = if data >= 1 << 30 {
        format!("{:.2} Gigabytes", data as f64 / (1 << 30) as f64)
    } else if data >= 1 << 20 {
        format!("{:.2} Megabytes", data as f64 / (1 << 20) as f64)
    } else if data >= 1 << 10 {
        format!("{:.2} Kilobytes", data as f64 / (1 << 10) as f64)
    } else {
        format!("{} bytes", data)
    };

    println!("Each algorithm will encrypt and decrypt {friendly} of data");

    if input.contains(&"aegis128".to_string()) {
        bench_aead!("AEGIS-128" => crypto::aegis::aegis_128 > Aegis128Enc | Aegis128Dec = data);
    }
    if input.contains(&"aegis256".to_string()) {
        bench_aead!("AEGIS-256" => crypto::aegis::aegis_256 > Aegis256Enc | Aegis256Dec = data);
    }
    if input.contains(&"aegis128L".to_string()) {
        bench_aead!("AEGIS-128L" => crypto::aegis::aegis_128L > Aegis128LEnc | Aegis128LDec = data);
    }
    if input.contains(&"aegis128X2".to_string()) {
        bench_aead!("AEGIS-128X2" => crypto::aegis::aegis_128X2 > Aegis128X2Enc | Aegis128X2Dec = data);
    }
    if input.contains(&"aegis128X4".to_string()) {
        bench_aead!("AEGIS-128X4" => crypto::aegis::aegis_128X4 > Aegis128X4Enc | Aegis128X4Dec = data);
    }
    if input.contains(&"aegis256X2".to_string()) {
        bench_aead!("AEGIS-256X2" => crypto::aegis::aegis_256X2 > Aegis256X2Enc | Aegis256X2Dec = data);
    }
    if input.contains(&"aegis256X4".to_string()) {
        bench_aead!("AEGIS-256X4" => crypto::aegis::aegis_256X4 > Aegis256X4Enc | Aegis256X4Dec = data);
    }

    Ok(())
}
