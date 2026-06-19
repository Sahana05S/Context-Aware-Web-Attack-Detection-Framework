import { Badge } from "./Badge";

interface SeverityBadgeProps {
    severity: string;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
    const normalized = severity.toUpperCase();

    let variant: "default" | "secondary" | "destructive" | "outline" | "success" | "warning" | "danger" | "info" = "outline";

    switch (normalized) {
        case "CRITICAL": variant = "destructive"; break;
        case "HIGH":     variant = "danger";      break;
        case "MEDIUM":   variant = "warning";     break;
        case "LOW":      variant = "success";     break;
        case "INFO":     variant = "info";        break;
        default:         variant = "outline";     break;
    }

    return (
        <Badge variant={variant} className="uppercase font-mono">
            {severity}
        </Badge>
    );
}
