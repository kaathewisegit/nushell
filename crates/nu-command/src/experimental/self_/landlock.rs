use landlock::{
    ABI, Access, AccessFs, AccessNet, NetPort, PathBeneath, PathFd, RestrictionStatus, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetError, RulesetStatus,
};

use nu_engine::command_prelude::*;

#[derive(Clone)]
pub struct Landlock;

fn abi(engine_state: &EngineState, stack: &mut Stack, call: &Call) -> Result<ABI, ShellError> {
    let Some(version) = call.get_flag::<i64>(engine_state, stack, "abi")? else {
        return Ok(ABI::V6);
    };

    if !(1..=6).contains(&version) {}

    Ok(match version {
        1 => ABI::V1,
        2 => ABI::V2,
        3 => ABI::V3,
        4 => ABI::V4,
        5 => ABI::V5,
        6 => ABI::V6,

        _ => {
            panic!("TODO error")
        }
    })
}

fn ports(
    engine_state: &EngineState,
    stack: &mut Stack,
    call: &Call,
    name: &str,
) -> Result<Vec<u16>, ShellError> {
    if let Ok(Some(port)) = call.get_flag::<u16>(engine_state, stack, name) {
        return Ok(vec![port]);
    }

    let Ok(ports) = call.get_flag::<Vec<u16>>(engine_state, stack, name) else {
        panic!("TODO error handling");
    };

    Ok(ports.unwrap_or(vec![]))
}

fn restrict(
    abi: ABI,
    no_new_privs: bool,
    bind: &[u16],
    connect: &[u16],
) -> Result<RestrictionStatus, RulesetError> {
    let access_all = AccessFs::from_all(abi);
    let access_read = AccessFs::from_read(abi);
    let access_rw = AccessFs::from_write(abi) | access_read;

    let access_net = AccessNet::from_all(abi);

    let mut ruleset = Ruleset::default()
        .handle_access(access_all)?
        .handle_access(access_net)?
        .create()?
        .set_no_new_privs(no_new_privs)
        .add_rule(PathBeneath::new(PathFd::new("/usr").unwrap(), access_read))?
        .add_rule(PathBeneath::new(PathFd::new("/lib").unwrap(), access_read))?
        .add_rule(PathBeneath::new(PathFd::new("/etc").unwrap(), access_read))?
        .add_rule(PathBeneath::new(
            PathFd::new("/home/kaathewise/.config/git/").unwrap(),
            access_read,
        ))?
        .add_rule(PathBeneath::new(PathFd::new("/tmp").unwrap(), access_rw))?
        .add_rule(PathBeneath::new(
            PathFd::new("/dev/null").unwrap(),
            access_rw,
        ))?
        .add_rule(PathBeneath::new(
            PathFd::new("/home/kaathewise/fork").unwrap(),
            access_rw,
        ))?;

    for port in bind {
        ruleset = ruleset.add_rule(NetPort::new(*port, AccessNet::BindTcp))?;
    }
    for port in connect {
        ruleset = ruleset.add_rule(NetPort::new(*port, AccessNet::ConnectTcp))?;
    }

    ruleset.restrict_self()
}

fn one_or_many_ss(shape: SyntaxShape) -> SyntaxShape {
    SyntaxShape::OneOf(vec![shape.clone(), SyntaxShape::List(Box::new(shape))])
}

impl Command for Landlock {
    fn name(&self) -> &str {
        "self landlock"
    }

    fn signature(&self) -> Signature {
        Signature::build(self.name())
            .category(Category::Experimental)
            .input_output_types(vec![(Type::Nothing, Type::Any)])
            .named(
                "abi",
                SyntaxShape::Number,
                "Landlock ABI version to use.  6 by default",
                None,
            )
            .switch("allow-new-privs", "Don't set NO_NEW_PRIVS", None)
            .named(
                "bind-tcp",
                one_or_many_ss(SyntaxShape::Number),
                "Allow binding these TCP ports",
                None,
            )
            .named(
                "connect-tcp",
                one_or_many_ss(SyntaxShape::Number),
                "Allow connecting to these TCP ports",
                None,
            )
    }

    fn description(&self) -> &str {
        "Apply landlock restrictions to the current Nu process"
    }

    fn examples(&self) -> Vec<Example> {
        // TODO
        vec![]
    }

    fn run(
        &self,
        engine_state: &EngineState,
        stack: &mut Stack,
        call: &Call,
        _input: PipelineData,
    ) -> Result<PipelineData, ShellError> {
        let abi = abi(engine_state, stack, call)?;
        let bind = ports(engine_state, stack, call, "bind-tcp")?;
        let connect = ports(engine_state, stack, call, "connect-tcp")?;
        let no_new_privs = !call.has_flag(engine_state, stack, "allow-new-privs")?;

        let status = restrict(abi, no_new_privs, &bind, &connect).unwrap();

        let span = call.span();

        let mut out = Record::new();

        let ruleset_status = match status.ruleset {
            RulesetStatus::FullyEnforced => Value::bool(true, span),
            RulesetStatus::PartiallyEnforced => Value::string("partially", span),
            RulesetStatus::NotEnforced => Value::bool(false, span),
        };
        out.insert("enforced", ruleset_status);
        out.insert("no_new_privs", Value::bool(no_new_privs, span));

        let out = Value::record(out, span);

        Ok(out.into_pipeline_data())
    }
}
