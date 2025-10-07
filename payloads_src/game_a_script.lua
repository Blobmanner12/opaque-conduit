--[[
  Source code for Game A script.
  This is human-readable and will be the input for the obfuscator.
--]]

print("Opaque-Conduit: Payload for Game A has been successfully decrypted and executed.")

-- Your premium script logic begins here.
local player = game:GetService("Players").LocalPlayer
local character = player.Character or player.CharacterAdded:Wait()

print("Payload running for user: " .. player.Name)

-- Example functionality:
local humanoid = character:WaitForChild("Humanoid")
if humanoid then
    humanoid.WalkSpeed = 50
    print("Increased WalkSpeed to 50.")
end