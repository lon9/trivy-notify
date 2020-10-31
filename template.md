{{ range . }}
Target: {{ .Target }}
Vulnerabilities:{{ range .Vulnerabilities }}
    ID: {{ .VulnerabilityID }}
    Severity: {{ .Severity }}
    PkgName: {{ .PkgName }}
    InstalledVersion: {{ .InstalledVersion }}
    FixedVersion: {{ .FixedVersion }}
{{ end }}{{ end }}
