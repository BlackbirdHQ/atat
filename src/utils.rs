use crate::{MaxCommandLen, MaxResponseLines};
use heapless::{String, Vec};

pub fn split_parameterized_resp(
    response_lines: &Vec<String<MaxCommandLen>, MaxResponseLines>,
) -> Vec<Vec<&str, MaxResponseLines>, MaxResponseLines> {
    // Handle list items
    response_lines
        .iter()
        .rev()
        .map(|response_line| {
            // parse response lines for parameters
            let mut v: Vec<&str, MaxResponseLines> = response_line
                .rsplit(|c: char| c == ':' || c == ',')
                .filter(|s| !s.is_empty())
                .collect();

            if v.len() > 1 {
                v.pop();
                v.reverse();
            }
            v
        })
        .collect()
}

pub fn split_parameterized_unsolicited(response_line: &str) -> (&str, Vec<&str, MaxResponseLines>) {
    let mut parameters: Vec<&str, MaxResponseLines> = response_line
        .rsplit(|c: char| c == ':' || c == ',')
        .filter(|s| !s.is_empty())
        .collect();

    let cmd = parameters.pop().unwrap();
    parameters.reverse();
    (cmd, parameters)
}
