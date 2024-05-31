#[cfg(test)]
mod tests {
    use crate::schiffy::{SSchiffy, encrypt};
    use crate::helper::vec_to_hex_string;

    #[test]
    fn test_sschiffy_new() {
        let key: u128 = 0xdeadbeef000000000000000badc0ffee;
        let schiffy = SSchiffy::new(key);

        assert_eq!(schiffy.s[0], 170);
        assert_eq!(schiffy.s[1], 155);
        assert_eq!(schiffy.s[2], 112);
        assert_eq!(schiffy.s[123], 33);
        assert_eq!(schiffy.s[255], 205);

        assert_eq!(schiffy.round_keys[0], 0xdeadbeef000000000000000bad6b3201);
        assert_eq!(schiffy.round_keys[1], 0x56df778000000000000005d6b532cd00);
        assert_eq!(schiffy.round_keys[2], 0xdde00000000000000175ad4cb3ebd858);
        assert_eq!(schiffy.round_keys[31], 0x770feb4b3180dc3bc09870bd38e2cb5f);
    }

    #[test]
    fn test_sschiffy_f() {
        let key: u128 = 0xdeadbeef000000000000000badc0ffee;
        let schiffy = SSchiffy::new(key);

        assert_eq!(schiffy.f(0, 0x0000000000000000), 0x94dfb49607c198ab);
        assert_eq!(schiffy.f(1, 0x94dfb49607c198ab), 0xb0aa7cca50e95fb1);
        assert_eq!(schiffy.f(2, 0xb0aa7cca50e95fb1), 0x1e9d6324e9783573);
        assert_eq!(schiffy.f(3, 0x8a42d7b2eeb9add8), 0x01a6283b0f33c8f0);
        
        assert_eq!(schiffy.f(29, 0xc8ef99ba72f8a579), 0xf7ffea032144154a);
        assert_eq!(schiffy.f(30, 0x81f3d4d01743d570), 0x7fac6b4146d4f4c6);
        assert_eq!(schiffy.f(31, 0xb743f2fb342c51bf), 0x2a66d3471f7cb499);
    }

    #[test]
    fn test_encrypt() {
        let key: u128 = 0xdeadbeef000000000000000badc0ffee;
        let encrypted = encrypt(key, "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00");

        assert_eq!(vec_to_hex_string(encrypted), "b743f2fb342c51bfab950797083f61e9");
    }

}
