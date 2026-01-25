#[macro_export]
macro_rules! exploit {
    ($exploit:ty, $proto:expr) => {{
        #[cfg(not(feature = "no_exploits"))]
        {
            if $proto.patch {
                let mut exploit = <$exploit>::new();

                if let Ok(result) = exploit.run($proto).await {
                    $proto.patch = !result;

                    if let Some(patched_da) = exploit.get_patched_da() {
                        $proto.da = patched_da;
                    }
                }
            }
        }
    }};
}
