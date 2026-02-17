//! Tests that parse real captured stream-json output from Claude CLI.
//!
//! These fixtures were captured from `claude -p --output-format stream-json --verbose`
//! and contain the full event sequence including hooks, init, assistant turns,
//! tool use, tool results, and final results.

use gleisner_tui::claude::QueryConfig;
use gleisner_tui::stream::{self, ContentBlock, StreamEvent, UserContentBlock};

/// Parse all lines from a fixture file and return (parsed, failed) counts.
fn parse_fixture(fixture: &str) -> (Vec<StreamEvent>, Vec<String>) {
    let mut parsed = Vec::new();
    let mut failed = Vec::new();

    for line in fixture.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        match stream::parse_event(line) {
            Some(event) => parsed.push(event),
            None => failed.push(line.to_owned()),
        }
    }

    (parsed, failed)
}

#[test]
fn simple_response_parses_completely() {
    let fixture = include_str!("fixtures/simple_response.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines:\n{}",
        failed.len(),
        failed
            .iter()
            .map(|l| {
                let preview = if l.len() > 200 {
                    format!("{}...", &l[..200])
                } else {
                    l.clone()
                };
                // Try to get the serde error for debugging
                let err = serde_json::from_str::<StreamEvent>(l)
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_default();
                format!("  {preview}\n  ERROR: {err}")
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    );

    // Verify expected event sequence
    assert!(
        parsed.len() >= 4,
        "expected at least 4 events (hooks + init + assistant + result), got {}",
        parsed.len()
    );

    // Check we got an init event
    let has_init = parsed
        .iter()
        .any(|e| matches!(e, StreamEvent::System(sys) if sys.subtype == "init"));
    assert!(has_init, "expected an init event in simple response");

    // Check we got an assistant response
    let has_assistant = parsed
        .iter()
        .any(|e| matches!(e, StreamEvent::Assistant(_)));
    assert!(
        has_assistant,
        "expected an assistant event in simple response"
    );

    // Check we got a result
    let has_result = parsed
        .iter()
        .any(|e| matches!(e, StreamEvent::Result(r) if !r.is_error));
    assert!(has_result, "expected a success result event");
}

#[test]
fn tool_use_response_parses_completely() {
    let fixture = include_str!("fixtures/tool_use_response.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines:\n{}",
        failed.len(),
        failed
            .iter()
            .map(|l| {
                let preview = if l.len() > 200 {
                    format!("{}...", &l[..200])
                } else {
                    l.clone()
                };
                let err = serde_json::from_str::<StreamEvent>(l)
                    .err()
                    .map(|e| e.to_string())
                    .unwrap_or_default();
                format!("  {preview}\n  ERROR: {err}")
            })
            .collect::<Vec<_>>()
            .join("\n\n")
    );

    // Should have more events due to tool use round-trips
    assert!(
        parsed.len() >= 5,
        "expected at least 5 events (hooks + init + assistant/tool + user/result + assistant + result), got {}",
        parsed.len()
    );

    // Check for tool_use content block
    let has_tool_use = parsed.iter().any(|e| {
        if let StreamEvent::Assistant(asst) = e {
            asst.message
                .content
                .iter()
                .any(|b| matches!(b, ContentBlock::ToolUse { .. }))
        } else {
            false
        }
    });
    assert!(has_tool_use, "expected a tool_use content block");

    // Check for tool_result
    let has_tool_result = parsed.iter().any(|e| {
        if let StreamEvent::User(user) = e {
            user.message
                .content
                .iter()
                .any(|b| matches!(b, UserContentBlock::ToolResult { .. }))
        } else {
            false
        }
    });
    assert!(has_tool_result, "expected a tool_result content block");
}

#[test]
fn result_event_captures_cost_and_session() {
    let fixture = include_str!("fixtures/simple_response.jsonl");
    let (parsed, _) = parse_fixture(fixture);

    let result = parsed
        .iter()
        .find_map(|e| {
            if let StreamEvent::Result(r) = e {
                Some(r)
            } else {
                None
            }
        })
        .expect("should have a result event");

    // Cost should be present and positive
    assert!(
        result.total_cost_usd.unwrap_or(0.0) > 0.0,
        "expected positive cost, got {:?}",
        result.total_cost_usd
    );

    // Session ID should be present
    assert!(
        result.session_id.is_some(),
        "expected session_id in result event"
    );

    // Duration should be present
    assert!(
        result.duration_ms.is_some(),
        "expected duration_ms in result event"
    );
}

#[test]
fn init_event_has_rich_metadata() {
    let fixture = include_str!("fixtures/simple_response.jsonl");
    let (parsed, _) = parse_fixture(fixture);

    let init = parsed
        .iter()
        .find_map(|e| {
            if let StreamEvent::System(sys) = e {
                if sys.subtype == "init" {
                    Some(sys)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .expect("should have an init event");

    // Model should be set
    assert!(init.model.is_some(), "expected model in init event");

    // Tools should be populated
    let tools = init.tools.as_ref().expect("expected tools in init event");
    assert!(!tools.is_empty(), "expected non-empty tools list");

    // Should have Claude Code version
    assert!(
        init.claude_code_version.is_some(),
        "expected claude_code_version in init event"
    );

    // Session ID should be present
    assert!(
        init.session_id.is_some(),
        "expected session_id in init event"
    );
}

/// Feed all fixture events through the App's stream event handler
/// and verify it updates state correctly.
#[test]
fn app_processes_simple_response_stream() {
    use gleisner_tui::app::{App, SessionState};

    let fixture = include_str!("fixtures/simple_response.jsonl");
    let (parsed, _) = parse_fixture(fixture);

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;

    for event in parsed {
        app.handle_stream_event(event);
    }

    // After processing, session should be idle (result received)
    assert_eq!(
        app.session_state,
        SessionState::Idle,
        "expected Idle after result event"
    );

    // Session ID should be captured
    assert!(
        app.session_id.is_some(),
        "expected session_id to be captured from init/result"
    );

    // Cost should be recorded
    assert!(
        app.security.cost_usd > 0.0,
        "expected cost to be recorded, got {}",
        app.security.cost_usd
    );

    // Should have at least one message (the assistant's response)
    let has_assistant_msg = app
        .messages
        .iter()
        .any(|m| matches!(m.role, gleisner_tui::app::Role::Assistant));
    assert!(has_assistant_msg, "expected at least one assistant message");
}

/// Feed tool-use fixture through the App and verify counters.
#[test]
fn app_processes_tool_use_stream() {
    use gleisner_tui::app::{App, SessionState};

    let fixture = include_str!("fixtures/tool_use_response.jsonl");
    let (parsed, _) = parse_fixture(fixture);

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;

    for event in parsed {
        app.handle_stream_event(event);
    }

    // Tool counters should reflect the Read call
    assert!(
        app.security.tool_calls > 0,
        "expected tool_calls > 0, got {}",
        app.security.tool_calls
    );
    assert!(
        app.security.file_reads > 0,
        "expected file_reads > 0 (Read tool was used), got {}",
        app.security.file_reads
    );

    // Should have tool messages
    assert!(
        app.messages
            .iter()
            .any(|m| matches!(m.role, gleisner_tui::app::Role::Tool)),
        "expected tool messages from Read call"
    );

    // Session should be idle
    assert_eq!(app.session_state, SessionState::Idle);

    // Turns should be recorded
    assert!(
        app.security.turns > 0,
        "expected turns > 0, got {}",
        app.security.turns
    );
}

// ─── Additional fixture tests ───────────────────────────────

#[test]
fn multi_tool_response_parses_completely() {
    let fixture = include_str!("fixtures/multi_tool_response.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines in multi_tool fixture",
        failed.len()
    );

    // Should have Glob and Bash tool calls
    let tool_names: Vec<&str> = parsed
        .iter()
        .filter_map(|e| {
            if let StreamEvent::Assistant(asst) = e {
                Some(asst.message.content.iter().filter_map(|b| {
                    if let ContentBlock::ToolUse { name, .. } = b {
                        Some(name.as_str())
                    } else {
                        None
                    }
                }))
            } else {
                None
            }
        })
        .flatten()
        .collect();

    assert!(
        tool_names.contains(&"Glob"),
        "expected Glob tool call, got {tool_names:?}"
    );
    assert!(
        tool_names.contains(&"Bash"),
        "expected Bash tool call, got {tool_names:?}"
    );
}

#[test]
fn error_tool_result_parses_correctly() {
    let fixture = include_str!("fixtures/error_tool_response.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines in error_tool fixture",
        failed.len()
    );

    // Should have a tool_result with is_error=true
    let has_error_result = parsed.iter().any(|e| {
        if let StreamEvent::User(user) = e {
            user.message
                .content
                .iter()
                .any(|b| matches!(b, UserContentBlock::ToolResult { is_error: true, .. }))
        } else {
            false
        }
    });
    assert!(
        has_error_result,
        "expected a tool_result with is_error=true"
    );
}

#[test]
fn multi_turn_with_errors_parses_completely() {
    let fixture = include_str!("fixtures/multi_turn_with_errors.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines in multi_turn fixture",
        failed.len()
    );

    // Count tool calls and error results
    let tool_count: usize = parsed
        .iter()
        .filter(|e| {
            matches!(e, StreamEvent::Assistant(asst) if
                asst.message.content.iter().any(|b| matches!(b, ContentBlock::ToolUse { .. })))
        })
        .count();

    let error_results: usize = parsed
        .iter()
        .filter(|e| {
            matches!(e, StreamEvent::User(user) if
                user.message.content.iter().any(|b| matches!(b, UserContentBlock::ToolResult { is_error: true, .. })))
        })
        .count();

    assert!(
        tool_count >= 2,
        "expected at least 2 tool calls, got {tool_count}"
    );
    assert!(
        error_results >= 1,
        "expected at least 1 error result, got {error_results}"
    );
}

#[test]
fn web_search_response_parses_completely() {
    let fixture = include_str!("fixtures/web_search_response.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines in web_search fixture",
        failed.len()
    );

    // Should have multiple tool round-trips
    let assistant_count = parsed
        .iter()
        .filter(|e| matches!(e, StreamEvent::Assistant(_)))
        .count();

    assert!(
        assistant_count >= 3,
        "expected at least 3 assistant events (multi-turn web search), got {assistant_count}"
    );
}

/// Cross-fixture: verify all fixtures process through the App without panics
/// and always end in Idle state.
#[test]
fn all_fixtures_process_through_app_without_panic() {
    use gleisner_tui::app::{App, SessionState};

    let fixtures = [
        ("simple", include_str!("fixtures/simple_response.jsonl")),
        ("tool_use", include_str!("fixtures/tool_use_response.jsonl")),
        (
            "multi_tool",
            include_str!("fixtures/multi_tool_response.jsonl"),
        ),
        (
            "error_tool",
            include_str!("fixtures/error_tool_response.jsonl"),
        ),
        (
            "multi_turn",
            include_str!("fixtures/multi_turn_with_errors.jsonl"),
        ),
        (
            "web_search",
            include_str!("fixtures/web_search_response.jsonl"),
        ),
        (
            "disallowed_tools",
            include_str!("fixtures/disallowed_tools_response.jsonl"),
        ),
        (
            "parallel_tools",
            include_str!("fixtures/parallel_tools_response.jsonl"),
        ),
        (
            "serena_analysis",
            include_str!("fixtures/serena_analysis_response.jsonl"),
        ),
        ("context7", include_str!("fixtures/context7_response.jsonl")),
        ("edit_test", include_str!("fixtures/edit-test.jsonl")),
        ("cargo_test", include_str!("fixtures/cargo-test.jsonl")),
        ("build_test", include_str!("fixtures/build-test.jsonl")),
        (
            "code_review",
            include_str!("fixtures/code-review-test.jsonl"),
        ),
        ("resume_turn1", include_str!("fixtures/resume-turn1.jsonl")),
        ("resume_turn2", include_str!("fixtures/resume-turn2.jsonl")),
    ];

    for (name, fixture) in fixtures {
        let (parsed, _) = parse_fixture(fixture);

        let mut app = App::new("test-profile");
        app.session_state = SessionState::Streaming;

        for event in &parsed {
            app.handle_stream_event(event.clone());
        }

        assert_eq!(
            app.session_state,
            SessionState::Idle,
            "fixture '{name}' did not end in Idle state"
        );

        assert!(
            app.session_id.is_some(),
            "fixture '{name}' did not capture session_id"
        );

        assert!(
            app.security.cost_usd > 0.0,
            "fixture '{name}' did not record cost (got {})",
            app.security.cost_usd
        );
    }
}

/// Verify that --disallowedTools removes tools from the init event's tools list.
#[test]
fn disallowed_tools_absent_from_init() {
    let fixture = include_str!("fixtures/disallowed_tools_response.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines in disallowed_tools fixture",
        failed.len()
    );

    let init = parsed
        .iter()
        .find_map(|e| {
            if let StreamEvent::System(sys) = e {
                if sys.subtype == "init" {
                    Some(sys)
                } else {
                    None
                }
            } else {
                None
            }
        })
        .expect("should have an init event");

    let tools = init.tools.as_ref().expect("expected tools in init event");

    // These should be blocked by --disallowedTools
    assert!(
        !tools
            .iter()
            .any(|t| t == "mcp__plugin_serena_serena__execute_shell_command"),
        "execute_shell_command should be blocked by --disallowedTools"
    );
    assert!(
        !tools
            .iter()
            .any(|t| t == "mcp__plugin_serena_serena__create_text_file"),
        "create_text_file should be blocked by --disallowedTools"
    );

    // But serena's read-only analysis tools should still be present
    assert!(
        tools
            .iter()
            .any(|t| t == "mcp__plugin_serena_serena__read_file"),
        "serena read_file should still be available"
    );
    assert!(
        tools
            .iter()
            .any(|t| t == "mcp__plugin_serena_serena__find_symbol"),
        "serena find_symbol should still be available"
    );
}

/// Verify parallel tool use is captured — Read and Glob in same response.
#[test]
fn parallel_tool_use_parses_correctly() {
    let fixture = include_str!("fixtures/parallel_tools_response.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines in parallel_tools fixture",
        failed.len()
    );

    // Should have both Read and Glob tool calls
    let tool_names: Vec<&str> = parsed
        .iter()
        .filter_map(|e| {
            if let StreamEvent::Assistant(asst) = e {
                Some(asst.message.content.iter().filter_map(|b| {
                    if let ContentBlock::ToolUse { name, .. } = b {
                        Some(name.as_str())
                    } else {
                        None
                    }
                }))
            } else {
                None
            }
        })
        .flatten()
        .collect();

    assert!(
        tool_names.contains(&"Read"),
        "expected Read tool call, got {tool_names:?}"
    );
    assert!(
        tool_names.contains(&"Glob"),
        "expected Glob tool call, got {tool_names:?}"
    );
}

/// Process the parallel tools fixture through App and verify dashboard state.
#[test]
fn app_processes_parallel_tools_with_exo_self() {
    use gleisner_tui::app::{App, SessionState};

    let fixture = include_str!("fixtures/parallel_tools_response.jsonl");
    let (parsed, _) = parse_fixture(fixture);

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;

    for event in parsed {
        app.handle_stream_event(event);
    }

    assert_eq!(app.session_state, SessionState::Idle);

    // Should have file_reads from the Read tool
    assert!(
        app.security.file_reads > 0,
        "expected file_reads > 0 from Read tool"
    );

    // Exo-self should be detected from the hook_started events
    assert!(
        app.security.exo_self_active,
        "expected exo_self_active from SessionStart hook"
    );

    // Should have plugins detected
    assert!(
        app.security.plugin_count > 0,
        "expected plugins to be detected from init event"
    );

    // Permission mode should be bypassPermissions
    assert_eq!(
        app.security.permission_mode, "bypassPermissions",
        "expected bypassPermissions mode"
    );
}

/// Verify MCP tool calls (serena) are parsed as regular `tool_use` events.
#[test]
fn serena_mcp_tool_calls_parse_as_tool_use() {
    let fixture = include_str!("fixtures/serena_analysis_response.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines in serena_analysis fixture",
        failed.len()
    );

    // Should have MCP tool calls with mcp__ prefix
    let tool_names: Vec<&str> = parsed
        .iter()
        .filter_map(|e| {
            if let StreamEvent::Assistant(asst) = e {
                Some(asst.message.content.iter().filter_map(|b| {
                    if let ContentBlock::ToolUse { name, .. } = b {
                        Some(name.as_str())
                    } else {
                        None
                    }
                }))
            } else {
                None
            }
        })
        .flatten()
        .collect();

    assert!(
        tool_names
            .iter()
            .any(|n| n.starts_with("mcp__plugin_serena_serena__")),
        "expected serena MCP tool calls, got {tool_names:?}"
    );

    // Should have activate_project and get_symbols_overview
    assert!(
        tool_names.iter().any(|n| n.contains("activate_project")),
        "expected activate_project call"
    );
    assert!(
        tool_names
            .iter()
            .any(|n| n.contains("get_symbols_overview")),
        "expected get_symbols_overview call"
    );
}

/// Process serena analysis through App and verify MCP tools update counters.
#[test]
fn app_tracks_mcp_tool_calls_in_dashboard() {
    use gleisner_tui::app::{App, SessionState};

    let fixture = include_str!("fixtures/serena_analysis_response.jsonl");
    let (parsed, _) = parse_fixture(fixture);

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;

    for event in parsed {
        app.handle_stream_event(event);
    }

    assert_eq!(app.session_state, SessionState::Idle);

    // MCP tool calls should increment tool_calls counter
    assert!(
        app.security.tool_calls >= 3,
        "expected at least 3 tool_calls (activate + check_onboarding + get_symbols_overview), got {}",
        app.security.tool_calls
    );
}

/// Verify context7 MCP tool calls parse correctly and exercise network-dependent tools.
#[test]
fn context7_mcp_tool_calls_parse_correctly() {
    let fixture = include_str!("fixtures/context7_response.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines in context7 fixture",
        failed.len()
    );

    let tool_names: Vec<&str> = parsed
        .iter()
        .filter_map(|e| {
            if let StreamEvent::Assistant(asst) = e {
                Some(asst.message.content.iter().filter_map(|b| {
                    if let ContentBlock::ToolUse { name, .. } = b {
                        Some(name.as_str())
                    } else {
                        None
                    }
                }))
            } else {
                None
            }
        })
        .flatten()
        .collect();

    // Should have resolve-library-id and query-docs
    assert!(
        tool_names.iter().any(|n| n.contains("resolve-library-id")),
        "expected resolve-library-id call, got {tool_names:?}"
    );
    assert!(
        tool_names.iter().any(|n| n.contains("query-docs")),
        "expected query-docs call, got {tool_names:?}"
    );
}

/// Verify Write + Read + Bash tools work for file editing workflow.
#[test]
fn edit_workflow_parses_write_read_bash() {
    let fixture = include_str!("fixtures/edit-test.jsonl");
    let (parsed, failed) = parse_fixture(fixture);

    assert!(
        failed.is_empty(),
        "Failed to parse {} lines in edit-test fixture",
        failed.len()
    );

    let tool_names: Vec<&str> = parsed
        .iter()
        .filter_map(|e| {
            if let StreamEvent::Assistant(asst) = e {
                Some(asst.message.content.iter().filter_map(|b| {
                    if let ContentBlock::ToolUse { name, .. } = b {
                        Some(name.as_str())
                    } else {
                        None
                    }
                }))
            } else {
                None
            }
        })
        .flatten()
        .collect();

    assert!(tool_names.contains(&"Write"), "expected Write tool call");
    assert!(tool_names.contains(&"Read"), "expected Read tool call");
    assert!(tool_names.contains(&"Bash"), "expected Bash tool call");
}

/// Verify cargo build+test results parse and track through App.
#[test]
fn cargo_build_test_through_app() {
    use gleisner_tui::app::{App, SessionState};

    let fixture = include_str!("fixtures/build-test.jsonl");
    let (parsed, _) = parse_fixture(fixture);

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;

    for event in parsed {
        app.handle_stream_event(event);
    }

    assert_eq!(app.session_state, SessionState::Idle);

    // Bash commands should be counted as tool_calls
    assert!(
        app.security.tool_calls >= 2,
        "expected at least 2 tool_calls (build + test), got {}",
        app.security.tool_calls
    );
}

/// Verify multi-turn session resumption: turn 1 and turn 2 share `session_id`.
#[test]
fn multi_turn_session_resumption() {
    let turn1 = include_str!("fixtures/resume-turn1.jsonl");
    let turn2 = include_str!("fixtures/resume-turn2.jsonl");

    let (parsed1, _) = parse_fixture(turn1);
    let (parsed2, _) = parse_fixture(turn2);

    // Extract session_ids
    let sid1 = parsed1.iter().find_map(|e| {
        if let StreamEvent::Result(r) = e {
            r.session_id.clone()
        } else {
            None
        }
    });
    let sid2 = parsed2.iter().find_map(|e| {
        if let StreamEvent::Result(r) = e {
            r.session_id.clone()
        } else {
            None
        }
    });

    assert!(sid1.is_some(), "turn 1 should have session_id");
    assert!(sid2.is_some(), "turn 2 should have session_id");
    assert_eq!(
        sid1, sid2,
        "both turns should share the same session_id for resumption"
    );

    // Turn 2 should have Edit tool (bug fix)
    let has_edit = parsed2.iter().any(|e| {
        if let StreamEvent::Assistant(asst) = e {
            asst.message
                .content
                .iter()
                .any(|b| matches!(b, ContentBlock::ToolUse { name, .. } if name == "Edit"))
        } else {
            false
        }
    });
    assert!(has_edit, "turn 2 should use Edit to fix the bug");
}

/// Verify App tracks `file_writes` from Edit tool calls in dev workflow.
#[test]
fn app_tracks_edits_in_dev_workflow() {
    use gleisner_tui::app::{App, SessionState};

    let fixture = include_str!("fixtures/edit-test.jsonl");
    let (parsed, _) = parse_fixture(fixture);

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;

    for event in parsed {
        app.handle_stream_event(event);
    }

    // Write tool should increment file_writes
    assert!(
        app.security.file_writes > 0,
        "expected file_writes > 0 from Write tool"
    );
    // Read tool should increment file_reads
    assert!(
        app.security.file_reads > 0,
        "expected file_reads > 0 from Read tool"
    );
}

/// Verify session continuation: the `session_id` from one fixture
/// can be used to construct a `QueryConfig` for multi-turn.
#[test]
fn session_id_is_usable_for_continuation() {
    use gleisner_tui::app::{App, SessionState};
    use gleisner_tui::claude::QueryConfig;

    let fixture = include_str!("fixtures/simple_response.jsonl");
    let (parsed, _) = parse_fixture(fixture);

    let mut app = App::new("test-profile");
    app.session_state = SessionState::Streaming;

    for event in parsed {
        app.handle_stream_event(event);
    }

    // Build a continuation config
    let config = QueryConfig {
        prompt: "follow up question".into(),
        resume_session: app.session_id.clone(),
        ..QueryConfig::default()
    };

    assert!(
        config.resume_session.is_some(),
        "expected resume_session to be set from previous session_id"
    );
    let sid = config.resume_session.unwrap();
    assert!(!sid.is_empty(), "session_id should be non-empty");
}

/// Verify `QueryConfig::from_profile` reads settings from the profile TOML.
#[test]
fn query_config_from_profile_reads_plugin_policy() {
    // Load the konishi profile (available when running from workspace root)
    let Ok(profile) = gleisner_polis::profile::resolve_profile("konishi") else {
        return;
    };

    let config = QueryConfig::from_profile(&profile);

    // Should inherit skip_permissions from profile
    assert!(
        config.skip_permissions,
        "expected skip_permissions=true from konishi profile"
    );

    // Should have disallowed_tools from profile
    assert!(
        config
            .disallowed_tools
            .iter()
            .any(|t: &String| t.contains("execute_shell_command")),
        "expected execute_shell_command in disallowed_tools"
    );

    // Should have exo-self add_dir from profile
    assert!(
        config
            .add_dirs
            .iter()
            .any(|d: &String| d.contains("exo-self")),
        "expected exo-self dir in add_dirs, got {:?}",
        config.add_dirs
    );
}

/// Verify ashton-laval profile blocks more tools than konishi.
#[test]
fn ashton_laval_blocks_more_tools() {
    let Ok(konishi) = gleisner_polis::profile::resolve_profile("konishi") else {
        return;
    };
    let Ok(ashton) = gleisner_polis::profile::resolve_profile("ashton-laval") else {
        return;
    };

    let konishi_config = QueryConfig::from_profile(&konishi);
    let ashton_config = QueryConfig::from_profile(&ashton);

    assert!(
        ashton_config.disallowed_tools.len() > konishi_config.disallowed_tools.len(),
        "ashton-laval should block more tools ({}) than konishi ({})",
        ashton_config.disallowed_tools.len(),
        konishi_config.disallowed_tools.len()
    );

    // Ashton-laval should block playwright navigation
    assert!(
        ashton_config
            .disallowed_tools
            .iter()
            .any(|t: &String| t.contains("browser_navigate")),
        "ashton-laval should block browser_navigate"
    );

    // Ashton-laval should have no add_dirs (maximum isolation)
    assert!(
        ashton_config.add_dirs.is_empty(),
        "ashton-laval should have empty add_dirs for maximum isolation"
    );
}

/// Verify `SandboxConfig` can be attached to a `QueryConfig` and cloned.
#[test]
fn sandbox_config_round_trips_through_query_config() {
    use gleisner_tui::claude::SandboxConfig;
    use std::path::PathBuf;

    let Ok(profile) = gleisner_polis::profile::resolve_profile("konishi") else {
        return;
    };

    let mut config = QueryConfig::from_profile(&profile);
    config.prompt = "test prompt".into();
    config.sandbox = Some(SandboxConfig {
        profile,
        project_dir: PathBuf::from("/tmp/test-project"),
        extra_allow_network: vec![],
        extra_allow_paths: vec![],
    });

    // Clone should work (needed for tokio::spawn)
    let cloned = config;
    assert!(cloned.sandbox.is_some());

    let sandbox = cloned.sandbox.unwrap();
    assert_eq!(sandbox.profile.name, "konishi");
    assert_eq!(sandbox.project_dir, PathBuf::from("/tmp/test-project"));
    assert!(cloned.skip_permissions);
}

/// Verify sandboxed command includes bwrap with correct args.
#[test]
fn sandboxed_query_builds_bwrap_command() {
    use gleisner_tui::claude::SandboxConfig;
    use std::path::PathBuf;

    // Skip if bwrap is not installed
    if std::process::Command::new("bwrap")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }

    let Ok(profile) = gleisner_polis::profile::resolve_profile("konishi") else {
        return;
    };

    let mut config = QueryConfig::from_profile(&profile);
    config.prompt = "hello".into();
    config.sandbox = Some(SandboxConfig {
        profile: profile.clone(),
        project_dir: PathBuf::from("/tmp/test-project"),
        extra_allow_network: vec![],
        extra_allow_paths: vec![],
    });

    // Build the sandbox directly to verify the command structure
    let mut bwrap_profile = profile;
    if let Ok(home) = std::env::var("HOME") {
        let home_path = PathBuf::from(&home);
        if !bwrap_profile.filesystem.readonly_bind.contains(&home_path) {
            bwrap_profile.filesystem.readonly_bind.push(home_path);
        }
    }

    let sandbox =
        gleisner_polis::BwrapSandbox::new(bwrap_profile, PathBuf::from("/tmp/test-project"))
            .expect("bwrap should be found");

    let inner = vec![
        "claude".to_owned(),
        "-p".into(),
        "hello".into(),
        "--output-format".into(),
        "stream-json".into(),
    ];
    let (cmd, _policy_file) = sandbox.build_command(&inner, false);

    let args: Vec<&str> = cmd.get_args().filter_map(|a| a.to_str()).collect();

    // Should be a bwrap command
    assert_eq!(
        cmd.get_program().to_str().unwrap(),
        "bwrap",
        "outer command should be bwrap"
    );

    // Should include readonly bind for /usr
    assert!(args.contains(&"--ro-bind"), "should have --ro-bind");
    assert!(args.contains(&"/usr"), "should bind /usr");

    // Should include the inner claude command
    assert!(args.contains(&"claude"), "inner command should be claude");
    assert!(args.contains(&"stream-json"), "should pass stream-json");

    // Should die with parent
    assert!(
        args.contains(&"--die-with-parent"),
        "should die with parent"
    );

    // Should set chdir to project dir
    assert!(args.contains(&"--chdir"), "should set --chdir");
    assert!(
        args.contains(&"/tmp/test-project"),
        "should chdir to project dir"
    );

    // Network should be unshared (konishi has deny default)
    assert!(
        args.contains(&"--unshare-net"),
        "konishi profile should unshare network"
    );
}
