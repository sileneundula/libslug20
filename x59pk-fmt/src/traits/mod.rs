use crate::label::X59Label;

pub trait AsX59Label {
    fn add_x59_label(&self, x59_label: X59Label) -> String;
}