import json

SYSTEM_PROMPT = (
    "You are an assistant for a digital forensics analyst. Write a three to four sentence "
    "executive summary of the incident described in the JSON. Use only facts present in the JSON. "
    "Do not invent details and do not recommend actions."
)


class TemplateNarrator:
    def narrate(self, context):
        summary = context["summary"]
        severity = context["severity"]
        attack = context.get("attack")

        text = (
            f"Between {context['timeline']['first_seen']} and {context['timeline']['last_seen']}, "
            f"{summary['source_ip']} produced {summary['flows']} flagged flows against "
            f"{summary['target_hosts']} target host(s)."
        )
        if attack and attack["technique_id"]:
            text += (
                f" The behaviour matches {attack['technique_id']} {attack['technique']} "
                f"({attack['tactic']}) with {attack['confidence']} confidence."
            )
        else:
            text += " The behaviour did not match a known technique and needs manual triage."
        text += f" Severity is assessed as {severity['level']}."
        return text


class AnthropicNarrator:
    def __init__(self, model, max_tokens=400):
        import anthropic

        self.client = anthropic.Anthropic()
        self.model = model
        self.max_tokens = max_tokens

    def narrate(self, context):
        message = self.client.messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": json.dumps(context, default=str)}],
        )
        return message.content[0].text.strip()
