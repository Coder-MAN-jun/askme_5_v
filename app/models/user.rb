require 'openssl'

class User < ApplicationRecord
  ITERATIONS = 20000
  DIGEST = OpenSSL::Digest::SHA256.new
  VALID_USERNAME_REGEXP = /\A\w+\z/

  attr_accessor :password

  has_many :questions, dependent: :destroy

  before_validation :username_downcase, :email_downcase

  before_save :encrypt_password

  validates :email, presence: true,
                    uniqueness: true,
                    format: { with: URI::MailTo::EMAIL_REGEXP }
  validates :username, presence: true,
            uniqueness: true,
            length: { maximum: 40 },
            format: { with: VALID_USERNAME_REGEXP }
  validates :password, presence: true, confirmation: true, on: :create
  validates :avatar_url, format: { with: URI.regexp }, allow_blank: true
  validates :profile_color, format: { with: /\A#([a-f\d]{3}){1,2}\z/ }

  def self.hash_to_string(password_hash)
    password_hash.unpack('H*')[0]
  end

  def self.authenticate(email, password)
    email&.downcase!
    user = find_by(email: email)
    return nil unless user.present?
    if user.present? && user.password_hash == User.hash_to_string(OpenSSL::PKCS5.pbkdf2_hmac(password, user.password_salt, ITERATIONS, DIGEST.length, DIGEST))
      user
    else
      nil
    end
  end

  private

  def encrypt_password
    if password.present?
      self.password_salt = User.hash_to_string(OpenSSL::Random.random_bytes(16))
      self.password_hash = User.hash_to_string(
        OpenSSL::PKCS5.pbkdf2_hmac(self.password, self.password_salt, ITERATIONS, DIGEST.length, DIGEST)
      )
    end
  end

  def username_downcase
    username&.downcase!
  end

  def email_downcase
    email&.downcase!
  end
end
Эта библиотека понадобится нам для шифрования.
