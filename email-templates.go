package user

import (
	"github.com/go-bolo/bolo"
	"github.com/go-bolo/emails"
)

func AddEmailTemplates(app bolo.App) {
	emp := app.GetPlugin("emails")
	if emp != nil {
		emailPlugin := emp.(*emails.EmailPlugin)

		emailPlugin.AddEmailTemplate("AccontActivationEmail", &emails.EmailType{
			Label:          "Email de ativação após cadastro de conta de usuário",
			DefaultSubject: "Validação de e-mail no site {{siteName}}",
			DefaultHTML: `<p>Obrigado por se registrar no site {{siteName}}!</p>
<p>Oi {{displayName}},</p>
<p><a href="{{confirmUrl}}">Clique aqui</a> ou copie e cole o link abaixo para confirmar o seu endere&ccedil;o de email&nbsp;no site {{siteName}}</p>
<p>Confirm link: {{confirmUrl}}</p>
<p><br />Atenciosamente,<br />{{siteName}}<br />{{siteUrl}}</p>`,
			DefaultText: `Obrigado por se registrar no site {{siteName}}!

Oi {{displayName}},

Copie o link abaixo para confirmar o seu endereço de e-mail no site {{siteName}}

Confirm link: {{confirmUrl}}


Atenciosamente,
{{siteName}}
{{siteUrl}}`,
			TemplateVariables: map[string]*emails.TemplateVariable{
				"confirmUrl": {
					Example:     "/#example",
					Description: "URL de confirmação de conta de usuário",
				},
				"username": {
					Example:     "albertosouza",
					Description: "Nome único do novo usuário",
				},
				"displayName": {
					Example:     "Alberto",
					Description: "Nome de exibição do novo usuário",
				},
				"fullName": {
					Example:     "Alberto Souza",
					Description: "Nome completo do novo usuário",
				},
				"email": {
					Example:     "alberto@linkysystems.com",
					Description: "Email do novo usuário",
				},
				"siteName": {
					Example:     "Site Name",
					Description: "Nome desse site",
				},
				"siteUrl": {
					Example:     "/#example",
					Description: "URL desse site",
				},
			},
		})

		emailPlugin.AddEmailTemplate("AuthResetPasswordEmail", &emails.EmailType{
			Label:          "Email de troca de senha",
			DefaultSubject: `Resetar senha no site {{siteName}}`,
			DefaultHTML: `<p>Oi {{displayName}},</p>
<p>Algu&eacute;m (provavelmente voc&ecirc;) requisitou a mudan&ccedil;a de senha no&nbsp;{{siteName}}. Clique no link abaixo para mudar a sua senha.</p>
<p>Link para resetar a senha: {{resetPasswordUrl}}<br /><br />Ignore esse email se voc&ecirc; n&atilde;o deseja resetar a sua senha.</p>
<p><br />Atenciosamente,<br />{{siteName}}<br />{{siteUrl}}</p>`,
			DefaultText: `Oi {{displayName}},
Alguém (provavelmente você) requisitou a mudança de senha no {{siteName}}. Clique no link abaixo para mudar a sua senha.

Link para resetar a senha: {{resetPasswordUrl}}

Ignore esse email se você não deseja resetar a sua senha.


Atenciosamente,
{{siteName}}
{{siteUrl}}`,

			TemplateVariables: map[string]*emails.TemplateVariable{
				"userId": {
					Example:     "1",
					Description: "Id do usuário",
				},
				"username": {
					Example:     "alberto",
					Description: "Nome único do usuário",
				},
				"displayName": {
					Example:     "Alberto",
					Description: "Nome de exibição do usuário",
				},
				"siteName": {
					Example:     "Site Name",
					Description: "Nome desse site",
				},
				"siteUrl": {
					Example:     "/#example",
					Description: "URL desse site",
				},
				"resetPasswordUrl": {
					Example:     "http://linkysystems.com/example",
					Description: "URL de resetar a senha do usuário",
				},
				"token": {

					Example:     "akdçkdakskcappckscoakcapcksckacpsckp",
					Description: "Token to use in custom urls",
				},
			},
		})

		emailPlugin.AddEmailTemplate("AuthChangePasswordEmail", &emails.EmailType{

			Label:          "Email de aviso de troca de senha",
			DefaultSubject: `Aviso de mudança de senha no site {{siteName}}`,
			DefaultHTML: `<p>Oi {{displayName}},</p>
<p>A sua senha no site {{siteName}} foi alterada.</p>
<br />
<br />
<p>Atenciosamente,<br />{{siteName}}<br />{{siteUrl}}</p>`,
			DefaultText: `Oi {{displayName}},

A sua senha no site {{siteName}} foi alterada.


Atenciosamente,
{{siteName}}
{{siteUrl}}`,
			TemplateVariables: map[string]*emails.TemplateVariable{
				"username": {
					Example:     "alberto",
					Description: "Nome único do usuário",
				},
				"displayName": {
					Example: "Alberto",

					Description: "Nome de exibição do usuário",
				},
				"siteName": {
					Example:     "Site Name",
					Description: "Nome desse site",
				},
				"siteUrl": {
					Example:     "/#example",
					Description: "URL desse site",
				},
			},
		})
	}
}
