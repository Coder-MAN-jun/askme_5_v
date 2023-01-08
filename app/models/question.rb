class Question < ApplicationRecord
  belongs_to :user
  belongs_to :autror, class_name: 'User', optional: true
  validates :user, :text, presence: true, length: { maximum: 255 }
end
