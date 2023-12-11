use std::{fmt::{self, Write, Display}, str::FromStr, collections::HashMap, mem, borrow::Borrow, hash::Hash};

use abnf::types as at;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Color {
    /// `#(FF0A1B, FF0A2B)` -> `FF0A1B, FF0A2B`
    Color(String),
    /// `"str\"ing"` -> `str\"ing`
    Include(String),
}
impl Display for Color {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Color(color) => write!(f, "\"{color}\""),
            Self::Include(color) => write!(f, "#({color})"),
        }
    }
}
impl FromStr for Color {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if s.starts_with("#(") && s.ends_with(')') {
            Ok(Self::Color(s[2..s.len()-1].into()))
        } else if s.len() > 1 && s.starts_with('"') && s.ends_with('"') {
            Ok(Self::Include(s[1..s.len()-1].into()))
        } else {
            Err(())
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplayMeta<'a> {
    indent_level: usize,
    indent_str: &'a str,
    indented: bool,
    lf_str: &'a str,
    str: String,
    color_list: HashMap<String, String>,
}
impl DisplayMeta<'static> {
    pub fn new() -> Self {
        Self {
            indent_level: 0,
            indent_str: "    ",
            lf_str: "\n",
            indented: false,
            str: String::new(),
            color_list: HashMap::new(),
        }
    }

    pub fn color_list(&self) -> &HashMap<String, String> {
        &self.color_list
    }
}
impl<'a> DisplayMeta<'a> {
    pub fn new_with_indent_str(indent_str: &'a str) -> Self {
        Self {
            indent_str,
            ..Default::default()
        }
    }
    pub fn new_with_lf_str(lf_str: &'a str) -> Self {
        Self {
            lf_str,
            ..Default::default()
        }
    }
    pub fn new_with_indent_and_lf_str(indent_str: &'a str, lf_str: &'a str) -> Self {
        Self {
            indent_str,
            lf_str,
            ..Default::default()
        }
    }
    fn newline(&mut self) {
        self.str.push_str(self.lf_str);
        self.indented = false;
    }
    fn try_indent(&mut self) -> bool {
        if !self.indented {
            self.str.push_str(&self.indent_str.repeat(self.indent_level));
            self.indented = true;
            true
        } else {
            false
        }
    }
    fn write_oneline(&mut self, s: &str) {
        self.try_indent();
        self.str.push_str(s);
    }
    fn write_oneline_args(&mut self, args: fmt::Arguments<'_>) -> fmt::Result {
        self.try_indent();
        self.str.write_fmt(args)
    }
    fn with_block<T>(
        &mut self,
        f: impl FnOnce(&mut Self) -> T,
    ) -> T {
        self.indent_level += 1;
        let res = f(self);
        self.indent_level -= 1;
        res
    }
    fn color(&mut self, color: &Color) -> String {
        match color {
            Color::Color(color) => {
                let id = self.color_list.len();
                let name = format!("AnonColor-{id}");
                self.color_list.insert(name.clone(), color.into());
                name
            },
            Color::Include(color) => color.into(),
        }
    }
    /// 尝试插入一个color字段, 成功会加上换行
    fn insert_color(&mut self, color: Option<&Color>) {
        if let Some(color) = color {
            let color_name = text_to_string(&self.color(color));
            self.write_oneline_args(format_args!("color: {}", color_name)).unwrap();
            self.newline();
        }
    }
    pub fn str(&self) -> &str {
        self.str.as_ref()
    }
    pub fn into_str(self) -> String {
        self.str
    }
}
impl Default for DisplayMeta<'static> {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MTPattern {
    Match {
        regex: String,
        color: Option<Color>,
    },
    Include {
        name: String,
    },
    /// group: link (至少匹配一个)
    Link {
        color: Option<Color>,
        sub_patterns: Vec<Self>,
    },
    LinkAll {
        color: Option<Color>,
        sub_patterns: Vec<Self>,
    },
    Select {
        color: Option<Color>,
        sub_patterns: Vec<Self>,
    },
    Empty,
}
impl Default for MTPattern {
    fn default() -> Self {
        Self::Empty
    }
}
impl MTPattern {
    pub fn new_optional(pat: Self) -> Self {
        Self::Select {
            color: None,
            sub_patterns: vec![
                pat,
                Self::Empty,
            ]
        }
    }
    pub fn new_repeat_c(pat: Self, count: usize) -> Self {
        Self::LinkAll {
            color: None,
            sub_patterns: vec![pat; count],
        }
    }
    pub fn display(&self, meta: &mut DisplayMeta) {
        match self {
            MTPattern::Match { regex, color: None } => {
                meta.write_oneline_args(format_args!("{{match: /{regex}/}}")).unwrap();
            },
            MTPattern::Match { regex, color } => {
                meta.write_oneline("{");
                meta.newline();
                meta.with_block(|meta| {
                    meta.write_oneline_args(format_args!("match: /{regex}/")).unwrap();
                    meta.newline();
                    let color_name = text_to_string(&meta.color(color.as_ref().unwrap()));
                    meta.write_oneline_args(format_args!("0: {}", color_name)).unwrap();
                    meta.newline();
                });
                meta.write_oneline("}");
            },
            MTPattern::Include { name } => {
                let name = text_to_string(name);
                meta.write_oneline_args(format_args!("{{include: {name}}}")).unwrap();
            },
            MTPattern::Link { color, sub_patterns } => {
                meta.write_oneline("{");
                meta.newline();
                meta.with_block(|meta| {
                    meta.write_oneline("group: link");
                    meta.newline();
                    meta.insert_color(color.as_ref());
                    meta.write_oneline("contains: [");
                    meta.newline();
                    meta.with_block(|meta| {
                        for pat in sub_patterns {
                            pat.display(meta);
                            meta.newline();
                        }
                    });
                    meta.write_oneline("]");
                    meta.newline();
                });
                meta.write_oneline("}");
            },
            MTPattern::LinkAll { color, sub_patterns } => {
                meta.write_oneline("{");
                meta.newline();
                meta.with_block(|meta| {
                    meta.write_oneline("group: linkAll");
                    meta.newline();
                    meta.insert_color(color.as_ref());
                    meta.write_oneline("contains: [");
                    meta.newline();
                    meta.with_block(|meta| {
                        for pat in sub_patterns {
                            pat.display(meta);
                            meta.newline();
                        }
                    });
                    meta.write_oneline("]");
                    meta.newline();
                });
                meta.write_oneline("}");
            },
            MTPattern::Select { color, sub_patterns } => {
                meta.write_oneline("{");
                meta.newline();
                meta.with_block(|meta| {
                    meta.write_oneline("group: select");
                    meta.newline();
                    meta.insert_color(color.as_ref());
                    meta.write_oneline("contains: [");
                    meta.newline();
                    meta.with_block(|meta| {
                        for pat in sub_patterns {
                            pat.display(meta);
                            meta.newline();
                        }
                    });
                    meta.write_oneline("]");
                    meta.newline();
                });
                meta.write_oneline("}");
            },
            MTPattern::Empty => {
                meta.write_oneline("{match: /(?:)/}");
            },
        }
    }
    pub fn get_color(&self) -> Option<&Color> {
        match self {
            | Self::Empty
            | Self::Include { .. }
            => None,
            | Self::Match { color, .. }
            | Self::Link { color, .. }
            | Self::LinkAll { color, .. }
            | Self::Select { color, .. }
            => color.into(),
        }
    }
    /// 可以设置颜色的话返回旧颜色, 无法设置颜色则返回错误
    ///
    /// 也会将无法上色的元素进行包装
    pub fn set_color(&mut self, new_color: Color) -> Result<Option<Color>, &Self> {
        match self {
            | Self::Empty
            => Err(self),
            | Self::Include { .. }
            => {
                let this = mem::take(self);
                *self = Self::LinkAll {
                    color: new_color.into(),
                    sub_patterns: vec![this]
                };
                Ok(None)
            },
            | Self::Match { color, .. }
            | Self::Link { color, .. }
            | Self::LinkAll { color, .. }
            | Self::Select { color, .. }
            => Ok(color.replace(new_color)),
        }
    }
    fn as_optional_mut(&mut self) -> Option<&mut Self> {
        match self {
            Self::Select { sub_patterns, .. } => {
                match &mut sub_patterns[..] {
                    [optional, Self::Empty] => optional.into(),
                    _ => None,
                }
            },
            _ => None,
        }
    }

    /// 进行优化
    /// 例如
    /// `a (b c (d e) f) g` -> `a b c d e f g`
    /// `a / (b / (c / d))` -> `a / b / c / d`
    /// `a |> (b |> c) |> d` -> `a |> b |> c |> d` // `|>` is link op
    /// `a [b [c]]` -> `a |> b |> c`
    pub fn optimization(&mut self) {
        type S = MTPattern; // Self
        /// 尝试展开嵌套可选序列
        fn expand_optionals(this: &mut S) {
            if let S::LinkAll { color, sub_patterns } = this {
                if let [first, next] = &mut sub_patterns[..] {
                    if next.get_color().is_some()
                    && next.get_color() != (&*color).into() {
                        return;
                    }
                    if let Some(opt) = next.as_optional_mut() {
                        let (
                            first,
                            opt,
                            color,
                        ) = (
                            mem::take(first),
                            mem::take(opt),
                            mem::take(color),
                        );
                        *this = S::Link { color, sub_patterns: vec![
                            first,
                            opt,
                        ] }
                    }
                }
            }
        }
        /// 仅一个元素的组展开
        fn expand_one_pat(this: &mut S) {
            match this {
                | S::Link { color, sub_patterns }
                | S::LinkAll { color, sub_patterns }
                | S::Select { color, sub_patterns }
                => {
                    if sub_patterns.len() != 1 { return }
                    if color.is_some()
                    && sub_patterns.last().unwrap()
                        .get_color() != (&*color).into() { return }
                    *this = sub_patterns.pop().unwrap()
                },
                _ => (),
            }
        }
        /// 展开允许的嵌套序列
        fn expand_subs(this: &mut S) {
            macro_rules! do_sub_match {
                ($name:ident => $color:expr, $sub_patterns:expr) => {
                    let (color, sub_patterns) = ($color, $sub_patterns);
                    let mut i = 0;
                    while i < sub_patterns.len() {
                        match &mut sub_patterns[i] {
                            S::$name {
                                color: s_color,
                                sub_patterns: s_sub_patterns
                            }
                            if s_color.is_none() || s_color == color
                            => {
                                let len = s_sub_patterns.len();
                                let replace_with = mem::take(s_sub_patterns);
                                sub_patterns.splice(i..=i, replace_with);
                                i += len
                            },
                            _ => i += 1,
                        }
                    }
                };
            }
            macro_rules! do_match {
                ($($name:ident),+ $(,)?) => {
                    match this {
                        $(
                        S::$name { color, sub_patterns } => {
                            do_sub_match!($name => color, sub_patterns);
                        },
                        )+
                        _ => (),
                    }
                };
            }
            do_match! {
                Select,
                Link,
                LinkAll,
            };
        }
        /// 对子匹配器进行递归
        fn opt_sub_pats(this: &mut S) {
            match this {
                | S::Link { sub_patterns, .. }
                | S::LinkAll { sub_patterns, .. }
                | S::Select { sub_patterns, .. }
                => sub_patterns.iter_mut().for_each(S::optimization),
                | _
                => (),
            }
        }
        opt_sub_pats(self);
        expand_optionals(self);
        expand_subs(self);
        expand_one_pat(self);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MTDefine {
    name: String,
    pattern: MTPattern,
}
impl MTDefine {
    pub fn new(name: String, pattern: MTPattern) -> Self {
        Self { name, pattern }
    }

    /// 新建一个重复零次至无穷
    ///
    /// `name = (pat name /)`
    pub fn new_zero_to(pat: MTPattern, name: String) -> Self {
        MTDefine {
            name: name.clone(),
            pattern: MTPattern::new_optional(MTPattern::LinkAll {
                color: None,
                sub_patterns: vec![
                    pat,
                    MTPattern::Include {
                        name,
                    },
                ],
            }),
        }
    }

    /// 新建一个重复一次至无穷
    ///
    /// `name = pat (name /)`
    pub fn new_one_to(pat: MTPattern, name: String) -> Self {
        MTDefine {
            name: name.clone(),
            pattern: MTPattern::LinkAll {
                color: None,
                sub_patterns: vec![
                    pat,
                    MTPattern::new_optional(MTPattern::Include {
                        name,
                    }),
                ],
            },
        }
    }

    pub fn display(&self, meta: &mut DisplayMeta) {
        let name = text_to_string(&self.name);
        meta.write_oneline_args(format_args!("{name}: ")).unwrap();
        self.pattern.display(meta);
        meta.newline();
    }

    pub fn optimization(&mut self) {
        self.pattern.optimization()
    }

    pub fn name(&self) -> &str {
        self.name.as_ref()
    }

    pub fn pattern(&self) -> &MTPattern {
        &self.pattern
    }

    pub fn set_pattern(&mut self, pattern: MTPattern) {
        self.pattern = pattern;
    }

    pub fn set_name(&mut self, name: String) {
        self.name = name;
    }

    pub fn pattern_mut(&mut self) -> &mut MTPattern {
        &mut self.pattern
    }
}

/// 处理为字符串
pub fn text_to_string(s: &str) -> String {
    let mut res = String::with_capacity(s.len() + 2);
    res.push('"');
    for ch in s.chars() {
        if let ..='\x1f' = ch {
            res.push_str(match ch {
                ' '.. => unreachable!(),
                '\n' => r"\n",
                '\r' => r"\r",
                '\t' => r"\t",
                ch => {
                    res.push_str(&format!("\\x{:x}", ch as u8));
                    continue;
                },
            });
            continue;
        }
        match ch {
            | '\\' | '"'
            => res.push('\\'),
            | _ => (),
        }
        res.push(ch)
    }
    res.push('"');
    res
}

/// 将文本转换为MT的正则, 转义序列将被替换掉
pub fn text_to_regex(s: &str) -> String {
    let mut res = String::with_capacity(s.len());
    for ch in s.chars() {
        if let ..='\x1f' = ch {
            res.push_str(match ch {
                ' '.. => unreachable!(),
                '\n' => r"\n",
                '\r' => r"\r",
                '\t' => r"\t",
                ch => {
                    res.push_str(&format!("\\x{:x}", ch as u8));
                    continue;
                },
            });
            continue;
        }
        match ch {
            | '/' | '*' | '+' | '?' | '('
            | ')' | '!' | '[' | ']' | '{'
            | '}' | '.' | '\\'| '|' | '^'
            | '$' | '-'
            => res.push('\\'),
            | _ => (),
        }
        res.push(ch)
    }
    res
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    defines: Vec<MTDefine>,
    anon_define_counter: usize,
    top_define_colors: Vec<(String, String)>,
}
impl Meta {
    pub fn new() -> Self {
        Self {
            defines: Vec::new(),
            anon_define_counter: 0,
            top_define_colors: Vec::new(),
        }
    }
    pub fn push(&mut self, define: MTDefine) {
        self.defines.push(define)
    }
    fn get_anon_name(&mut self) -> String {
        let name = format!("anonrule-{}", self.anon_define_counter);
        self.anon_define_counter += 1;
        name
    }
    #[allow(dead_code)]
    fn new_anon_define(&mut self, pat: MTPattern) -> String {
        let name = self.get_anon_name();
        self.push(MTDefine::new(name.clone(), pat));
        name
    }
    pub fn into_defines(self) -> Vec<MTDefine> {
        self.defines
    }

    pub fn defines(&self) -> &[MTDefine] {
        self.defines.as_ref()
    }

    pub fn optimization(&mut self) {
        self.defines.iter_mut().for_each(MTDefine::optimization)
    }

    /// 设置所有定义的颜色, 但是不包括子定义
    /// 如出现同名则仅设置第一个
    ///
    /// 使用闭包收集每个设置颜色的返回
    /// 使用另一个闭包进行失败处理
    ///
    /// 会将使用的颜色从哈希表中删除
    pub fn set_colors<Q, F, F1>(
        &mut self,
        colors: &mut HashMap<Q, Color>,
        mut f: F,
        mut fail: F1,
    )
    where Q: Hash + Eq + Borrow<str>,
          F: FnMut(Result<Option<Color>, &MTPattern>),
          F1: FnMut(&MTDefine)
    {
        for define in &mut self.defines {
            let name = define.name();
            if let Some(color) = colors.remove(name) {
                f(define.pattern.set_color(color))
            } else {
                fail(define)
            }
        }
    }

    pub fn display(&self, meta: &mut DisplayMeta) {
        for define in self.defines() {
            define.display(meta);
        }
    }

    pub fn top_define_colors(&self) -> &[(String, String)] {
        self.top_define_colors.as_ref()
    }
}

impl Default for Meta {
    fn default() -> Self {
        Self::new()
    }
}

pub fn node_to_mtsx(node: &at::Node, meta: &mut Meta) -> MTPattern {
    use {
        at::{
            Node,
            TerminalValues as TV,
            Repeat,
        },
        MTPattern as MTP,
    };
    match node {
        Node::Alternatives(nodes) => MTP::Select {
            color: None,
            sub_patterns: nodes.iter()
                .map(|node| node_to_mtsx(node, meta))
                .collect()
        },
        Node::Concatenation(nodes) => MTP::LinkAll {
            color: None,
            sub_patterns: nodes.iter()
                .map(|node| node_to_mtsx(node, meta))
                .collect()
        },
        Node::Repetition { repeat: Repeat::Specific(0), .. }
        | Node::Repetition {
            repeat: Repeat::Variable { max: Some(0), .. },
            ..
        } => {
            MTP::Empty
        },
        Node::Repetition { repeat: Repeat::Specific(count), node } => {
            MTP::new_repeat_c(node_to_mtsx(node, meta), *count)
        },
        Node::Repetition { // min == max
            repeat: Repeat::Variable { min: Some(min), max: Some(max) },
            node
        } if max == min => {
            MTP::new_repeat_c(node_to_mtsx(node, meta), *min)
        },
        Node::Repetition { repeat: Repeat::Variable { min, max }, node } => {
            if min.is_some() { assert_ne!(max, min); }
            let pat = node_to_mtsx(node, meta);
            let min = min.unwrap_or_default();
            let next = max.map(|max| max - min);
            let mut first = vec![pat.clone(); min];
            match next {
                Some(next) => {
                    if first.pop().is_none() {
                        MTP::new_optional(MTP::Link {
                            color: None,
                            sub_patterns: vec![pat; next],
                        })
                    } else {
                        assert_ne!(next, 0);
                        first.push(MTP::Link {
                            color: None,
                            sub_patterns: vec![pat; next + 1],
                        });
                        MTP::LinkAll {
                            color: None,
                            sub_patterns: first,
                        }
                    }
                },
                None => { // 无右界
                    let next_name = meta.get_anon_name();
                    if first.pop().is_none() {
                        // 没之前的, 直接新建一个零开始的无穷匹配
                        meta.push(MTDefine::new_zero_to(pat, next_name.clone()));
                        MTP::Include { name: next_name }
                    } else {
                        // 有之前的, 那么弹出一个并且新建至少一个的无穷匹配
                        meta.push(MTDefine::new_one_to(pat, next_name.clone()));
                        first.push(MTP::Include { name: next_name });
                        if first.len() == 1 {
                            first.pop().unwrap()
                        } else {
                            MTP::LinkAll { color: None, sub_patterns: first }
                        }
                    }
                },
            }
        },
        Node::Rulename(name) => MTP::Include { name: name.into() },
        Node::Group(node) => node_to_mtsx(node, meta),
        Node::Optional(node) => MTP::new_optional(node_to_mtsx(node, meta)),
        Node::String(stringlit) => MTP::Match {
            regex: if stringlit.is_case_sensitive() {
                text_to_regex(stringlit.value())
            } else {
                format!("(?i){}", text_to_regex(stringlit.value()))
            },
            color: None,
        },
        Node::TerminalValues(TV::Range(start, end)) => MTP::Match {
            regex: format!(
                       "[{}-{}]",
                       text_to_regex(&char::from_u32(*start).unwrap().to_string()),
                       text_to_regex(&char::from_u32(*end).unwrap().to_string()),
            ),
            color: None
        },
        Node::TerminalValues(TV::Concatenation(nums)) => MTP::Match {
            regex: text_to_regex(&String::from_iter(
                           nums
                           .iter()
                           .map(|&num| char::from_u32(num).unwrap()))),
            color: None
        },
        // 直接表示为正则
        Node::Prose(str)
        if str.len() > 2 && str.starts_with('/') && str.ends_with('/') => {
            MTP::Match { regex: str[1..str.len()-1].into(), color: None }
        },
        // 当做引用处理
        Node::Prose(str) => MTP::Include { name: str.into() },
    }
}
pub fn rulelist_to_mtsx(rulelist: &[at::Rule]) -> Meta {
    let mut meta = Meta::new();
    let mut index = HashMap::new();
    for rule in rulelist {
        let name = rule.name();
        let node = rule.node();
        let mtsx = node_to_mtsx(node, &mut meta);
        if let Some(&id) = index.get(name) {
            let prev_define: &mut MTDefine = &mut meta.defines[id];
            let prev_mtsx = mem::take(&mut prev_define.pattern);
            let _ = mem::replace(&mut prev_define.pattern, MTPattern::Select {
                color: None,
                sub_patterns: vec![
                    prev_mtsx,
                    mtsx,
                ]
            });
        } else {
            let define = MTDefine::new(name.into(), mtsx);
            let id = meta.defines().len();
            meta.push(define);
            index.insert(name, id);
        }
    }
    meta
}

#[cfg(test)]
mod tests {
    use super::*;

    mod optimization_test {
        use super::*;

        #[test]
        fn expand_select_subs_test() {
            let mut pat = MTPattern::Select {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::Select {
                        color: None,
                        sub_patterns: vec![
                            MTPattern::Match { regex: "b".into(), color: None },
                            MTPattern::Match { regex: "c".into(), color: None },
                        ],
                    },
                    MTPattern::Match { regex: "d".into(), color: None },
                ],
            };
            pat.optimization();
            assert_eq!(pat, MTPattern::Select {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::Match { regex: "b".into(), color: None },
                    MTPattern::Match { regex: "c".into(), color: None },
                    MTPattern::Match { regex: "d".into(), color: None },
                ],
            });
        }

        #[test]
        fn expand_linkall_subs_test() {
            let mut pat = MTPattern::LinkAll {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::LinkAll {
                        color: None,
                        sub_patterns: vec![
                            MTPattern::Match { regex: "b".into(), color: None },
                            MTPattern::Match { regex: "c".into(), color: None },
                        ],
                    },
                    MTPattern::Match { regex: "d".into(), color: None },
                ],
            };
            pat.optimization();
            assert_eq!(pat, MTPattern::LinkAll {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::Match { regex: "b".into(), color: None },
                    MTPattern::Match { regex: "c".into(), color: None },
                    MTPattern::Match { regex: "d".into(), color: None },
                ],
            });
        }

        #[test]
        fn expand_link_subs_test() {
            let mut pat = MTPattern::Link {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::Link {
                        color: None,
                        sub_patterns: vec![
                            MTPattern::Match { regex: "b".into(), color: None },
                            MTPattern::Match { regex: "c".into(), color: None },
                        ],
                    },
                    MTPattern::Match { regex: "d".into(), color: None },
                ],
            };
            pat.optimization();
            assert_eq!(pat, MTPattern::Link {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::Match { regex: "b".into(), color: None },
                    MTPattern::Match { regex: "c".into(), color: None },
                    MTPattern::Match { regex: "d".into(), color: None },
                ],
            });
        }

        #[test]
        fn tail_options_test() {
            let mut pat = MTPattern::LinkAll {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::new_optional(
                        MTPattern::Match { regex: "b".into(), color: None }
                    ),
                ],
            };
            pat.optimization();
            assert_eq!(pat, MTPattern::Link {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::Match { regex: "b".into(), color: None },
                ],
            });
            let mut pat = MTPattern::LinkAll {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::new_optional(
                        MTPattern::LinkAll {
                            color: None,
                            sub_patterns: vec![
                                MTPattern::Match { regex: "b".into(), color: None },
                                MTPattern::new_optional(
                                    MTPattern::Match { regex: "c".into(), color: None }
                                ),
                            ],
                        }
                    ),
                ],
            };
            pat.optimization();
            assert_eq!(pat, MTPattern::Link {
                color: None,
                sub_patterns: vec![
                    MTPattern::Match { regex: "a".into(), color: None },
                    MTPattern::Match { regex: "b".into(), color: None },
                    MTPattern::Match { regex: "c".into(), color: None },
                ],
            });
        }

        #[test]
        fn expand_one_pat_test() {
            let mut pat = MTPattern::LinkAll {
                color: None,
                sub_patterns: vec![
                    MTPattern::LinkAll {
                        color: None,
                        sub_patterns: vec![
                            MTPattern::LinkAll {
                                color: None,
                                sub_patterns: vec![
                                    MTPattern::Match { regex: "a".into(), color: None },
                                ],
                            },
                        ],
                    },
                ],
            };
            pat.optimization();
            assert_eq!(pat, MTPattern::Match { regex: "a".into(), color: None });
        }
    }

    #[test]
    fn set_colors_test() {
        let rulelist = abnf::rulelist(concat!(
                "foo = bar / baz\n",
        )).unwrap();
        let mut meta = rulelist_to_mtsx(&rulelist);
        meta.set_colors(
            &mut HashMap::from([
                ("foo", Color::Include("x".into())),
            ]),
            |_| (),
            |def| panic!("{:?}", def),
        );
        assert_eq!(
            meta.defines()[0].pattern().get_color(),
            Some(&Color::Include("x".into())),
        );
    }

    #[test]
    fn color_from_str_test() {
        assert_eq!("#(a, b)".parse(), Ok(Color::Color("a, b".into())));
        assert_eq!("\"ab\"".parse(), Ok(Color::Include("ab".into())));
    }

    #[test]
    fn text_to_regex_test() {
        let datas: &[[&str; 2]] = &[
            ["", r""],
            ["x", r"x"],
            ["x\n\r", r"x\n\r"],
            ["x\t\x1b", r"x\t\x1b"],
            [".([{}])\\-*+?/", r"\.\(\[\{\}\]\)\\\-\*\+\?\/"],
        ];
        for &[src, dst] in datas {
            assert_eq!(text_to_regex(src), dst);
        }
    }

    #[test]
    fn text_to_string_test() {
        let datas: &[[&str; 2]] = &[
            ["", r#""""#],
            ["\"", r#""\"""#],
            ["x", r#""x""#],
            ["x\n\r", r#""x\n\r""#],
            ["x\t\x1b", r#""x\t\x1b""#],
        ];
        for &[src, dst] in datas {
            assert_eq!(text_to_string(src), dst);
        }
    }
}
