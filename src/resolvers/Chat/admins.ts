import { User } from "../../models";
import type { ChatResolvers } from "../../types/generatedGraphQLTypes";
/**
 * This resolver function will fetch and return the list of all chat admins from the database.
 * @param parent - An object that is the return value of the resolver for this field's parent.
 * @returns An `object` that contains the list of users.
 */
export const admins: ChatResolvers["users"] = async (parent) => {
  return await User.find({
    _id: {
      $in: parent.admins,
    },
  }).lean();
};
