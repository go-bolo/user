package user_models

import (
	"time"

	"github.com/go-bolo/bolo"
	"github.com/go-bolo/bolo/helpers"
)

// module.exports = function Model(we) {
//   // set sequelize model define and options
//   return {
//     definition: {
//       userId: {
//         type: we.db.Sequelize.BIGINT,
//         allowNull: false
//       },
//       providerUserId: { type: we.db.Sequelize.BIGINT },
//       tokenProviderId: { type: we.db.Sequelize.STRING },
//       tokenType: { type: we.db.Sequelize.STRING },
//       token: {
//         type: we.db.Sequelize.STRING,
//         defaultValue: true
//       },
//       isValid: {
//         type: we.db.Sequelize.BOOLEAN,
//         defaultValue: true
//       },
//       redirectUrl: { type: we.db.Sequelize.STRING }
//     },
//     options: {
//       enableAlias: false,
//       classMethods: {
//         /**
//          * Invalid old user tokens
//          * @param  {string}   uid  user id to invalid all tokens
//          * @param  {Function} next callback
//          */
//         invalidOldUserTokens(uid, next) {
//           we.db.user_models.authtoken
//           .update(
//             { isValid : false },
//             { where: {
//               userId: uid
//             }}
//           )
//           .nodeify(next)
//         },

//         /**
//         * Check if a auth token is valid
//         */
//         validAuthToken(userId, token, cb) {
//           // then get user token form db
//           we.db.user_models.authtoken
//           .findOne({ where: {
//             token: token,
//             userId: userId
//           }})
//           .then( (authToken)=> {
//             // auth token found then check if is valid
//             if (!authToken) {
//               // auth token not fount
//               return cb (null, false, null)
//             } else if(authToken.userId != userId || !authToken.isValid) {
//             // user id how wons the auth token is invalid then return false
//               cb(null, false,{
//                 result: 'invalid',
//                 message: 'Invalid token'
//               });
//             } else  {
//               return authToken.destroy()
//               .then( ()=> {
//                 // authToken is valid
//                 cb(null, true, authToken);

//                 return null;
//               })
//             }
//             return null;
//           })
//           .catch(cb);
//         }
//       },
//       instanceMethods: {
//         /**
//          * Get record reset Url
//          *
//          * @return {String}
//          */
//         getResetUrl() {
//           return we.config.hostname + '/auth/'+ this.userId +'/reset-password/' + this.token;
//         },
//         /**
//          * toJson method
//          * @return {Object}
//          */
//         toJSON() {
//           return this.get();
//         }
//       },
//       hooks: {
//         /**
//          * Before create one record
//          *
//          * @param  {Object}   token   record instance
//          * @param  {Object}   options sequelize create options
//          * @param  {Function} next    callback
//          */
//         beforeCreate(token) {
//           return new Promise( (resolve)=> {
//             if (token.userId) {
//               // before create, set all user old tokens as invalid:
//               we.db.user_models.authtoken.invalidOldUserTokens(token.userId, function() {
//                 // generete new token
//                 token.token = crypto.randomBytes(25).toString('hex');
//                 resolve();
//               });
//             } else {
//               resolve();
//             }
//           });

//         }
//       }
//     }
//   };
// }

type AuthTokenModel struct {
	ID              uint64  `gorm:"primary_key;column:id;" json:"id" filter:"param:id;type:number"`
	UserID          *string `gorm:"index:userId;column:userId;type:int(11)" json:"userId" filter:"param:userId;type:number"`
	ProviderUserID  int64   `gorm:"column:providerUserId;type:BIGINT" json:"providerUserId" filter:"param:providerUserId;type:string"`
	TokenProviderID string  `gorm:"column:tokenProviderId;type:VARCHAR(255)" json:"tokenProviderId" filter:"param:tokenProviderId;type:string"`

	TokenType   string `gorm:"column:tokenType;type:VARCHAR(255)" json:"tokenType" filter:"param:tokenType;type:string"`
	Token       string `gorm:"column:token;type:VARCHAR(255)" json:"token" filter:"param:token;type:string"`
	IsValid     bool   `gorm:"column:isValid" json:"isValid" filter:"param:isValid;type:bool"`
	RedirectURL string `gorm:"column:redirectUrl;type:TEXT" json:"redirectUrl" filter:"param:redirectUrl;type:string"`

	CreatedAt time.Time `gorm:"column:createdAt;" json:"createdAt" filter:"param:createdAt"`
	UpdatedAt time.Time `gorm:"column:updatedAt;" json:"updatedAt" filter:"param:updatedAt"`
}

func (r *AuthTokenModel) TableName() string {
	return "authtokens"
}

func (r *AuthTokenModel) Delete() error {
	db := bolo.GetDefaultDatabaseConnection()
	return db.Unscoped().Delete(&r).Error
}

func (r *AuthTokenModel) Save() error {
	db := bolo.GetDefaultDatabaseConnection()

	if r.ID == 0 {
		if r.Token == "" {
			r.Token = helpers.RandStringBytes(35)
		}

		// create ....
		err := db.Create(&r).Error
		if err != nil {
			return err
		}
	} else {
		// update ...
		err := db.Save(&r).Error
		if err != nil {
			return err
		}
	}

	return nil
}

func (r *AuthTokenModel) GetResetUrl(ctx *bolo.RequestContext) string {
	baseUrl := ctx.AppOrigin
	return baseUrl + "/auth/" + *r.UserID + "/forgot-password/reset?t=" + r.Token
}

func FindInvalidOldUserTokens(uid string) ([]*AuthTokenModel, error) {
	var tokens []*AuthTokenModel

	db := bolo.GetDefaultDatabaseConnection()

	err := db.Model(&AuthTokenModel{}).
		Where("userId = ? AND isValid = ?", uid, false).
		Find(&tokens).
		Error

	return tokens, err
}

func ValidAuthToken(userID string, token string) (bool, *AuthTokenModel, error) {
	var authToken AuthTokenModel

	db := bolo.GetDefaultDatabaseConnection()

	err := db.Model(&AuthTokenModel{}).
		Where("token = ? AND userId = ?", token, userID).
		First(&authToken).
		Error

	if err != nil {
		return false, nil, err
	}

	if !authToken.IsValid {
		return false, nil, nil
	}

	return true, &authToken, nil
}

func FindOneAuthToken(id string) (*AuthTokenModel, error) {
	db := bolo.GetDefaultDatabaseConnection()

	var token AuthTokenModel

	err := db.Model(&AuthTokenModel{}).
		Where("id = ?", id).
		First(&token).
		Error

	return &token, err
}

func CreateAuthToken(userID, tokenType string) (*AuthTokenModel, error) {
	t := AuthTokenModel{
		UserID:    &userID,
		TokenType: tokenType,
		IsValid:   true,
	}

	err := t.Save()
	return &t, err
}
