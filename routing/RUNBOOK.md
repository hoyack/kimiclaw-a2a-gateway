# Bot-task routing runbook (EP09, A2A-71)

## Assign a task to a bot
Add exactly one label `owner_<bot>` (rivet, tugboat, critic, bastion, cpo, cto, brandon) and leave it in **To Do**.
Within one poll (~5 min) the bot's poller:
1. re-checks the task is still To Do and has no `[<bot>] picked up` comment,
2. moves it to **In Progress** and comments `[<bot>] picked up`,
3. sends `<KEY>: <summary>\n\n<description>` to the gateway over A2A (`message/send`, non-blocking; taskId = contextId = issue key), then polls `tasks/get`,
4. comments `[<bot>] result` followed by the reply. Status stays In Progress for the bot/owner to move.

All writes use the one service account, so the `[<bot>]` prefix is the signature.

## Failure modes
| What | What you see | What to do |
|---|---|---|
| Gateway/Jira transient error | up to 3 tries (1s, 4s backoff) | nothing |
| Gateway down, agent failed, or timeout (15 min) | `[<bot>] failed: <type>`, task back in To Do | fix cause, delete that bot's `picked up` and `failed` comments to re-queue |
| 0 or 2+ `owner_` labels, empty summary | task ignored | fix labels; `python3 -m routing.cli lint` lists offenders |
| Jira down at claim | poll output lists key under `failed`, no comment | retried next poll |

Comments never include payloads, tokens, or exception text: only the error type.

## Pause a bot
Deactivate its n8n workflow `A2A routing: <bot>`. Remove the label from a single task to pull just that task.

## Onboard a new bot
1. Add the name to `BOTS` in `routing/router.py` and run `python3 routing/n8n/build.py`.
2. If it has its own A2A endpoint, set `A2A_GATEWAY_URL_<BOT>` on the n8n host.
3. Import `routing/n8n/poller-<bot>.json` in n8n, check it, activate it.
4. Put one test task in To Do with `owner_<bot>`; expect `picked up` then one `result` comment.

## Setup (n8n host)
Env: `A2A_ROUTING_DIR` (checkout path), `JIRA_BASE_URL`, `JIRA_EMAIL` (service account), `JIRA_API_TOKEN`, `A2A_GATEWAY_URL`, `A2A_GATEWAY_TOKEN`.
Values come from the n8n credentials provisioned in A2A-63; never put them in the workflow JSON, tickets, or git.
`flock -n` stops overlapping runs of the same bot's poller.
