package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"html/template"
	"log"
	"net/http"
)

type CertInfo struct {
	CommonName         string
	SubjectAltNames    []string
	Organization       []string
	OrganizationalUnit []string
	Locality           []string
	State              []string
	Country            []string
	ValidFrom          string
	ValidTo            string
	Issuer             string
	KeySize            int
	SerialNumber       string
}

var templates *template.Template

func main() {
	// Parse all templates in the templates directory
	templates = template.Must(template.ParseGlob("templates/*.html"))

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/process", processHandler)
	log.Println("Server started at :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	err := templates.ExecuteTemplate(w, tmpl, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	renderTemplate(w, "index.html", nil)
}

func processHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	certPEM := r.FormValue("cert")
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		http.Error(w, "Invalid certificate", http.StatusBadRequest)
		return
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		http.Error(w, "Failed to parse certificate", http.StatusInternalServerError)
		return
	}

	certInfo := CertInfo{
		CommonName:         cert.Subject.CommonName,
		SubjectAltNames:    cert.DNSNames,
		Organization:       cert.Subject.Organization,
		OrganizationalUnit: cert.Subject.OrganizationalUnit,
		Locality:           cert.Subject.Locality,
		State:              cert.Subject.Province,
		Country:            cert.Subject.Country,
		ValidFrom:          cert.NotBefore.String(),
		ValidTo:            cert.NotAfter.String(),
		Issuer:             cert.Issuer.CommonName + ", " +  cert.Issuer.Organization[0],
		KeySize:            cert.PublicKey.(*rsa.PublicKey).Size() * 8,
		SerialNumber:       cert.SerialNumber.String(),
	}

	renderTemplate(w, "index.html", certInfo)


}
