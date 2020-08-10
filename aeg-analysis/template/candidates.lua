{{TARGET_OBJECTS}}

ordered_key = {}
index = 1
for k, v in pairs(TargetObjects) do
  ordered_key[index] = k
  index = index + 1
end

Kmalloc = {
  [8192] = 32768,
  [4096] = 32768,
  [2048] = 32768,
  [1024] = 32768,
  [512]  = 16384,
  [256]  = 16384,
  [192]  = 4096,
  [128]  = 4096,
  [96]   = 4096,
  [64]   = 4096,
  [32]   = 4096,
  [16]   = 4096,
}

AlignedSizes = {}
index = 1
for k, v in pairs(Kmalloc) do
  AlignedSizes[index] = k 
  index = index + 1
end

function roundSize(size)
  local ret = 8192
  if (size > ret) then
    return math.ceil(size / 4096) * 4096
  end
  for k, v in pairs(Kmalloc) do
    if (k >= size and k < ret) then
      ret = k
    end
  end
  return ret
end

cur_index = 1
function getCandidate(size, isVariable, allocator)
    size = roundSize(size)
    while (cur_index <= #ordered_key) do
      local k = ordered_key[cur_index]
      local object = TargetObjects[k]
      cur_index = cur_index + 1
      if allocator == "slab" then
        if (isVariable or object["size"] == size) then
          return true, object["offset"], object["payload"], #object["payload"], object["size"]
        end
      elseif allocator == "page" then
        local vul_size = Kmalloc[object.size]
        if object.size >= 1024 and (isVariable or vul_size == size) then
          return true, object["offset"], object["payload"], #object["payload"], vul_size
        end
      else
        if (isVariable or object["size"] == size) then
          return true, object["offset"], object["payload"], #object["payload"], object["size"]
        end
      end
    end
    return false, 0, "", 0, size
end

-- getCandidate Must be called at least once before invoking getCurCandidate
function getCurCandidate()
  if (cur_index - 1 <= #ordered_key) then
    local k = ordered_key[cur_index - 1]
    local object = TargetObjects[k]
    return true, k
  end
  return false, ""
end

function getValues()
  local k = ordered_key[cur_index - 1]
  local object = TargetObjects[k]
  if object["hasvalue"] then
    return true, object["values"], #object["values"]
  else
    return true, "", 0
  end
end
